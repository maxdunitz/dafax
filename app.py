"""Ballot fax relay for in-person voter help.

A volunteer at a tabling event opens /mint and gets a QR code holding a
single-use token that expires in minutes. The voter scans it with their own
phone, uploads the scan they just took, types their clerk's fax number and
sends it themselves.

The shape of this is deliberate. The ballot never lands on a volunteer's
device, the voter transmits their own ballot, no account is created, nothing
identifying the voter is stored, and the PDF is deleted the moment Telnyx
reports a terminal status. What is left behind is a job record with a
destination, a page count and a status -- no image, no name, no address.

Because the send form is reachable by anyone holding a token, the security
model here is anti-abuse rather than authentication: an open fax relay sending
from our own number is a junk-fax liability and an easy way to burn the Telnyx
balance. Hence single-use tokens with a short life, a global daily page
ceiling, hard input limits and an optional Turnstile check.
"""

import base64
import datetime
import hashlib
import hmac
import io
import json
import os
import re
import secrets
from functools import wraps

import qrcode
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request, url_for)
from google.cloud import storage
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from PIL import Image, ImageOps
from pillow_heif import register_heif_opener
from pypdf import PdfReader

# iPhones hand out HEIC unless the voter went through the document scanner, so
# this has to be registered or half the uploads fail to open.
register_heif_opener()

app = Flask(__name__)

SECRET_KEY = os.environ["SECRET_KEY"]
app.secret_key = SECRET_KEY

VOLUNTEER_USER = (os.getenv("VOLUNTEER_USER") or "volunteer").strip()
VOLUNTEER_PASS = (os.getenv("VOLUNTEER_PASS") or "").strip()

BASE_URL = (os.getenv("BASE_URL") or "").rstrip("/")
# What a volunteer reads down the phone. Telnyx keeps using BASE_URL, so the
# fax path does not depend on the short domain staying up.
PUBLIC_HOST = (os.getenv("PUBLIC_HOST") or "").strip().rstrip("/")
GCS_BUCKET = os.environ["GCS_BUCKET"]

TELNYX_API_KEY = os.getenv("TELNYX_API_KEY") or ""
TELNYX_CONNECTION_ID = os.getenv("TELNYX_CONNECTION_ID") or ""
TELNYX_FROM = os.getenv("TELNYX_FROM") or ""
TELNYX_PUBLIC_KEY = os.getenv("TELNYX_PUBLIC_KEY") or ""

TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS") or 900)
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES") or 20 * 1024 * 1024)
MAX_PAGES = int(os.getenv("MAX_PAGES") or 10)
DAILY_PAGE_CAP = int(os.getenv("DAILY_PAGE_CAP") or 200)
MEDIA_URL_TTL = int(os.getenv("MEDIA_URL_TTL") or 900)
# How many times one token may fail before it stops being released for
# retry. Counted against the token, not the job: every retry is a new job.
MAX_SEND_FAILURES = int(os.getenv("MAX_SEND_FAILURES") or 5)

TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY") or ""
TURNSTILE_SECRET = os.getenv("TURNSTILE_SECRET") or ""

# Cloud Run enforces 32 MiB; stopping short of it gives a clearer error than a
# truncated request.
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + (1024 * 1024)

tokens = URLSafeTimedSerializer(SECRET_KEY, salt="dafax-token")

ALLOWED_IMAGE = {"image/jpeg", "image/png", "image/heic", "image/heif"}
FAX_WIDTH_PX = 1728          # the standard fax scanline, 8.5in at 204 dpi
FAX_DPI = 204

_storage = None


def bucket():
    """Lazily built so the app can boot (and /healthz can answer) without
    credentials -- useful locally and when Cloud Run probes a cold instance."""
    global _storage
    if _storage is None:
        _storage = storage.Client()
    return _storage.bucket(GCS_BUCKET)


def base_url():
    return BASE_URL or request.url_root.rstrip("/")


def public_base():
    """Where we send people, which is not where Telnyx talks to us.

    The QR code and the spoken address should both be the short domain, but
    the media fetch and the webhook keep using BASE_URL so that a fax in
    flight never depends on the custom domain or its certificate.
    """
    return ("https://" + PUBLIC_HOST) if PUBLIC_HOST else base_url()


## ---------------------------------------------------------------- volunteers


def requires_volunteer(f):
    @wraps(f)
    def wrapper(*a, **kw):
        auth = request.authorization
        ok = (auth and auth.username == VOLUNTEER_USER
              and VOLUNTEER_PASS
              and hmac.compare_digest(auth.password or "", VOLUNTEER_PASS))
        if not ok:
            return Response(
                "Volunteer login required", 401,
                {"WWW-Authenticate": 'Basic realm="Volunteers"'})
        return f(*a, **kw)
    return wrapper


## -------------------------------------------------------------------- tokens


def mint_token(minted_by):
    return tokens.dumps({"by": minted_by, "n": secrets.token_urlsafe(12)})


def read_token(raw):
    """Return the token payload, or None if it is forged or expired."""
    try:
        return tokens.loads(raw, max_age=TOKEN_TTL_SECONDS)
    except (BadSignature, SignatureExpired):
        return None


## ---------------------------------------------------------------- shout key


# Crockford base32: no I, L, O or U, so nothing is ambiguous when it is read
# down a phone line and nothing spells anything unfortunate.
SHOUT_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
SHOUT_LEN = 6
_SHOUT_FIX = str.maketrans({"I": "1", "L": "1", "O": "0"})


def new_shout_key():
    return "".join(secrets.choice(SHOUT_ALPHABET) for _ in range(SHOUT_LEN))


def normalize_shout_key(raw):
    """Accept what a voter actually types: case, spaces and hyphens are
    noise, and I/L/O are what people write when they hear 1/1/0."""
    s = re.sub(r"[^0-9A-Za-z]", "", raw or "").upper().translate(_SHOUT_FIX)
    if len(s) != SHOUT_LEN or any(c not in SHOUT_ALPHABET for c in s):
        return None
    return s


def human_ttl(seconds):
    """'3 days' reads better on the mint page than '4320 minutes'."""
    for unit, n in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= n and seconds % n == 0:
            v = seconds // n
            return "%d %s%s" % (v, unit, "" if v == 1 else "s")
    return "%d minutes" % max(1, seconds // 60)


def pretty_shout_key(code):
    half = SHOUT_LEN // 2
    return "%s-%s" % (code[:half], code[half:])


def store_shout_key(token):
    """A short code a volunteer can say out loud, pointing at a real token.

    The code carries no authority of its own: expiry and single-use still
    live in the signed token it resolves to, so a code is worthless the
    moment the fax is sent or the token ages out. if_generation_match=0
    means two volunteers can never be handed the same code.

    Six characters is 30 bits. With twenty codes live at once a blind guess
    lands about once in 54 million tries, so this leans on rate limiting at
    the edge rather than on entropy alone. What a hit actually buys is one
    fax of at most MAX_PAGES pages to one US or Canadian number, counted
    against the daily page cap and paid out of a deliberately small Telnyx
    balance -- a junk fax, not a foothold.
    """
    for _ in range(5):
        code = new_shout_key()
        try:
            bucket().blob("codes/%s" % code).upload_from_string(
                token.encode(), if_generation_match=0)
            return code
        except Exception:
            continue
    return None


def lookup_shout_key(code):
    blob = bucket().blob("codes/%s" % code)
    if not blob.exists():
        return None
    return blob.download_as_bytes().decode()


def claim_token(nonce):
    """Burn a token exactly once.

    if_generation_match=0 makes GCS reject the write if the object already
    exists, so two phones submitting the same QR code race and exactly one
    wins -- without a database.
    """
    blob = bucket().blob("used/%s" % nonce)
    try:
        blob.upload_from_string(b"1", if_generation_match=0)
        return True
    except Exception:
        return False


## ------------------------------------------------------------------ normalize


def _image_to_page(data):
    img = Image.open(io.BytesIO(data))
    img = ImageOps.exif_transpose(img)           # honour the phone's rotation
    img = ImageOps.grayscale(img)
    img = ImageOps.autocontrast(img)
    if img.width != FAX_WIDTH_PX:
        h = max(1, round(img.height * FAX_WIDTH_PX / img.width))
        img = img.resize((FAX_WIDTH_PX, h), Image.LANCZOS)
    # A plain threshold, not dithering: dithered text turns to mush at fax
    # resolution, and this is going to be read by a human at a clerk's office.
    return img.point(lambda p: 255 if p > 160 else 0, mode="1")


def normalize_to_pdf(files):
    """Turn what the voter uploaded into one PDF, and count its pages.

    A PDF passes through untouched -- the iOS document scanner already
    deskews, crops and thresholds, and Telnyx rasterises PDFs itself, so
    re-rendering one would only lose quality. Photos are converted, because a
    colour snapshot faxed as-is arrives as a dark smear.
    """
    pdfs = [f for f in files if (f.mimetype or "").lower() == "application/pdf"]
    imgs = [f for f in files if (f.mimetype or "").lower() in ALLOWED_IMAGE]
    if len(pdfs) + len(imgs) != len(files):
        raise ValueError("Please upload a PDF or photos (JPEG, PNG or HEIC).")
    if pdfs and imgs:
        raise ValueError("Please send either a single PDF or photos, not both.")

    if pdfs:
        if len(pdfs) > 1:
            raise ValueError("Please combine the pages into one PDF.")
        data = pdfs[0].read()
        try:
            pages = len(PdfReader(io.BytesIO(data)).pages)
        except Exception:
            raise ValueError("That PDF could not be read.")
        if pages == 0:
            raise ValueError("That PDF has no pages.")
        return data, pages

    if not imgs:
        raise ValueError("Nothing was attached.")
    pages = [_image_to_page(f.read()) for f in imgs]
    out = io.BytesIO()
    pages[0].save(out, format="PDF", save_all=True, append_images=pages[1:],
                  resolution=FAX_DPI)
    return out.getvalue(), len(pages)


## ----------------------------------------------------------------- job record


def new_job_id():
    day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    return "%s-%s" % (day, secrets.token_urlsafe(8))


def job_blob(job_id):
    return bucket().blob("jobs/%s/%s.json" % (job_id[:8], job_id))


def save_job(job, pages=None):
    blob = job_blob(job["job_id"])
    if pages is not None:
        # Kept in object metadata so the daily cap can be computed from a
        # listing, without downloading every record.
        blob.metadata = {"pages": str(pages)}
    blob.upload_from_string(json.dumps(job), content_type="application/json")


def load_job(job_id):
    blob = job_blob(job_id)
    if not blob.exists():
        return None
    return json.loads(blob.download_as_bytes())


def pages_today():
    day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    total = 0
    for b in bucket().list_blobs(prefix="jobs/%s/" % day):
        try:
            total += int((b.metadata or {}).get("pages") or 0)
        except (TypeError, ValueError):
            pass
    return total


## ------------------------------------------------------------- media handoff


def media_sig(job_id, exp):
    msg = ("%s|%s" % (job_id, exp)).encode()
    return hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()


def media_url(job_id):
    exp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + MEDIA_URL_TTL
    return "%s/m/%s?exp=%d&sig=%s" % (base_url(), job_id, exp,
                                      media_sig(job_id, exp))


## ------------------------------------------------------------------ Turnstile


def turnstile_ok():
    if not TURNSTILE_SECRET:
        return True
    try:
        r = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": TURNSTILE_SECRET,
                  "response": request.form.get("cf-turnstile-response", ""),
                  "remoteip": request.headers.get("CF-Connecting-IP", "")},
            timeout=8)
        return bool(r.json().get("success"))
    except Exception as e:
        print("turnstile check failed:", type(e).__name__, e)
        return False


## -------------------------------------------------------------- destinations

US_FAX = re.compile(r"^\+1[2-9]\d{9}$")


def clean_destination(raw):
    """Normalise to +1XXXXXXXXXX, or return None.

    Destinations are restricted to US and Canadian geographic numbers: a
    clerk's fax is always one, and it keeps the relay from being pointed at
    premium-rate or international numbers.
    """
    digits = re.sub(r"[^0-9]", "", raw or "")
    if len(digits) == 10:
        digits = "1" + digits
    candidate = "+" + digits
    if not US_FAX.match(candidate):
        return None
    if candidate[2:5] in ("900", "976"):     # premium rate
        return None
    if TELNYX_FROM and candidate == TELNYX_FROM:
        return None
    return candidate


## ----------------------------------------------------------------- send flow


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/", methods=["GET", "POST"])
def index():
    """Where a voter being helped over the phone starts.

    In person the QR code skips this entirely; this exists so a volunteer who
    cannot show a screen can read a code down the line instead.
    """
    if request.method != "POST":
        return render_template("index.html",
                               turnstile_site_key=TURNSTILE_SITE_KEY)

    def again(msg):
        return render_template("index.html", error=msg,
                               turnstile_site_key=TURNSTILE_SITE_KEY), 400

    # Six characters is 30 bits, so this form is the one place worth making
    # expensive to script against. Inert until TURNSTILE_SECRET is set.
    if not turnstile_ok():
        return again("That check did not pass. Please try again.")

    code = normalize_shout_key(request.form.get("code"))
    token = lookup_shout_key(code) if code else None
    # One message for every failure: a wrong code, an expired one and an
    # already-used one are deliberately indistinguishable from outside.
    if not token or not read_token(token):
        return again("That code did not work. It may have expired, or already "
                     "been used. Ask the volunteer helping you for a new one.")
    return redirect(url_for("send_form", token=token))


@app.route("/mint")
@requires_volunteer
def mint():
    """The page a volunteer keeps open at the table."""
    token = mint_token(request.authorization.username)
    link = "%s/s/%s" % (public_base(), token)

    img = qrcode.make(link)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr = base64.b64encode(buf.getvalue()).decode()

    code = store_shout_key(token)
    return render_template("mint.html", link=link, qr=qr,
                           code=pretty_shout_key(code) if code else None,
                           host=PUBLIC_HOST or base_url().split("://", 1)[-1],
                           valid_for=human_ttl(TOKEN_TTL_SECONDS))


@app.route("/s/<token>", methods=["GET"])
def send_form(token):
    if not read_token(token):
        return render_template("expired.html"), 410
    return render_template("send.html", token=token,
                           turnstile_site_key=TURNSTILE_SITE_KEY,
                           max_pages=MAX_PAGES,
                           max_mb=MAX_UPLOAD_BYTES // (1024 * 1024))


@app.route("/s/<token>", methods=["POST"])
def send(token):
    payload = read_token(token)
    if not payload:
        return render_template("expired.html"), 410

    def fail(msg):
        return render_template("send.html", token=token, error=msg,
                               turnstile_site_key=TURNSTILE_SITE_KEY,
                               max_pages=MAX_PAGES,
                               max_mb=MAX_UPLOAD_BYTES // (1024 * 1024)), 400

    if not turnstile_ok():
        return fail("That check did not pass. Please try again.")

    destination = clean_destination(request.form.get("to"))
    if not destination:
        return fail("That does not look like a US or Canadian fax number. "
                    "Check the number on your state's page and try again.")

    files = [f for f in request.files.getlist("doc") if f and f.filename]
    if not files:
        return fail("Please attach your scan.")

    try:
        pdf, pages = normalize_to_pdf(files)
    except ValueError as e:
        return fail(str(e))
    except Exception as e:
        print("normalise failed:", type(e).__name__, e)
        return fail("That file could not be read. A PDF from your phone's "
                    "document scanner works best.")

    if pages > MAX_PAGES:
        return fail("That is %d pages; the limit is %d." % (pages, MAX_PAGES))
    if pages_today() + pages > DAILY_PAGE_CAP:
        print("daily page cap reached")
        return fail("The service has hit its daily limit. Please tell the "
                    "volunteer helping you.")

    # Burn the token only once the submission is known to be good, so a voter
    # who mistypes the fax number is not sent back to the volunteer for a new
    # QR code.
    if not claim_token(payload["n"]):
        return render_template("expired.html"), 410

    job_id = new_job_id()
    bucket().blob("media/%s.pdf" % job_id).upload_from_string(
        pdf, content_type="application/pdf")

    job = {"job_id": job_id, "to": destination, "pages": pages,
           # Kept so a failed send can release the token again. Not a
           # credential on its own: the token itself is signed and is not
           # stored anywhere.
           "nonce": payload["n"],
           "minted_by": payload.get("by"), "status": "queued",
           "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "detail": ""}
    save_job(job, pages=pages)

    try:
        r = requests.post(
            "https://api.telnyx.com/v2/faxes",
            headers={"Authorization": "Bearer %s" % TELNYX_API_KEY},
            json={"connection_id": TELNYX_CONNECTION_ID,
                  "to": destination,
                  "from": TELNYX_FROM,
                  "media_url": media_url(job_id),
                  "webhook_url": "%s/telnyx" % base_url(),
                  "quality": "high"},
            timeout=20)
        r.raise_for_status()
        fax_id = r.json()["data"]["id"]
    except Exception as e:
        print("telnyx submit failed:", type(e).__name__, e,
              getattr(getattr(e, "response", None), "text", ""))
        job["status"] = "failed"
        job["detail"] = "Could not reach the fax provider."
        save_job(job, pages=pages)
        return fail("The fax could not be submitted. Please tell the "
                    "volunteer helping you.")

    job["telnyx_fax_id"] = fax_id
    save_job(job, pages=pages)
    # Telnyx only quotes its own id back to us on the webhook, so keep a
    # pointer home.
    bucket().blob("faxmap/%s" % fax_id).upload_from_string(job_id.encode())

    return render_template("status.html", job=job,
                           host=PUBLIC_HOST or base_url().split("://", 1)[-1]), 202


@app.route("/m/<job_id>")
def media(job_id):
    """Where Telnyx fetches the PDF.

    Signed and short-lived rather than public: this is a voted ballot, and it
    should be unreachable the moment the transmission is over.
    """
    try:
        exp = int(request.args.get("exp") or 0)
    except ValueError:
        abort(403)
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    if exp < now:
        abort(410)
    if not hmac.compare_digest(request.args.get("sig") or "",
                              media_sig(job_id, exp)):
        abort(403)

    blob = bucket().blob("media/%s.pdf" % job_id)
    if not blob.exists():
        abort(404)
    return Response(blob.download_as_bytes(), mimetype="application/pdf")


@app.route("/telnyx", methods=["POST"])
def telnyx_webhook():
    raw = request.get_data()
    if not verify_telnyx(raw):
        print("telnyx webhook signature rejected")
        abort(403)

    data = (request.get_json(silent=True) or {}).get("data") or {}
    event = data.get("event_type") or ""
    inner = data.get("payload") or {}
    fax_id = inner.get("fax_id") or inner.get("id")
    print("TELNYX EVENT:", event, fax_id, inner.get("failure_reason") or "")

    # Inbound. Assign a second Telnyx number to the same fax application and
    # this becomes a closed test loop: fax number one to number two and then
    # look at what actually came out the other end, which is the only honest
    # way to check a ballot is still legible after a fax.
    if event == "fax.received":
        return receive_fax(inner, fax_id)

    pointer = bucket().blob("faxmap/%s" % fax_id)
    if not fax_id or not pointer.exists():
        return "", 204
    job_id = pointer.download_as_bytes().decode()
    job = load_job(job_id)
    if not job:
        return "", 204

    job["status"] = {"fax.queued": "queued",
                     "fax.media.processed": "preparing",
                     "fax.sending.started": "sending",
                     "fax.delivered": "delivered",
                     "fax.failed": "failed"}.get(event, job.get("status"))
    if event == "fax.failed":
        job["detail"] = inner.get("failure_reason") or "The fax did not go through."
    save_job(job, pages=job.get("pages"))

    # Terminal: the ballot has no reason to exist any longer.
    if event in ("fax.delivered", "fax.failed"):
        for name in ("media/%s.pdf" % job_id, "faxmap/%s" % fax_id):
            try:
                bucket().blob(name).delete()
            except Exception as e:
                print("cleanup of", name, "failed:", type(e).__name__, e)

    # A clerk's line is busy more often than anything else goes wrong, and
    # the token was already burned before Telnyx was ever called. Release it
    # so the voter can re-enter the same spoken code instead of queueing for
    # a new one -- the scan is gone either way, but the code need not be.
    if event == "fax.failed" and job.get("nonce"):
        # The counter lives beside the burn marker rather than on the job,
        # because each retry is a fresh job and would otherwise reset it.
        # The ".fails" suffix keeps it clear of the exact-name claim check
        # while still inheriting the used/ lifecycle rule.
        counter = bucket().blob("used/%s.fails" % job["nonce"])
        try:
            n = int(counter.download_as_bytes()) if counter.exists() else 0
        except Exception:
            n = 0
        n += 1
        try:
            counter.upload_from_string(str(n).encode())
        except Exception as e:
            print("failure counter write failed:", type(e).__name__, e)

        if n < MAX_SEND_FAILURES:
            try:
                bucket().blob("used/%s" % job["nonce"]).delete()
                print("released token for retry:", job_id, "failure", n)
            except Exception as e:
                print("token release failed:", type(e).__name__, e)
        else:
            print("retry cap reached for", job_id, "after", n, "failures")

    return "", 204


def receive_fax(inner, fax_id):
    """Store an inbound fax so a volunteer can look at it.

    This exists to test the pipeline, not to collect ballots: the bucket's
    one-day lifecycle rule deletes whatever lands here, and the only numbers
    pointed at it should be ones we own.
    """
    url = inner.get("media_url")
    if not url or not fax_id:
        return "", 204

    body = None
    # Telnyx has served this both ways; try authenticated first.
    for headers in ({"Authorization": "Bearer %s" % TELNYX_API_KEY}, {}):
        try:
            r = requests.get(url, headers=headers, timeout=30)
            if r.ok and r.content:
                body = r.content
                break
        except Exception as e:
            print("inbound fax fetch failed:", type(e).__name__, e)
    if not body:
        print("inbound fax", fax_id, "could not be fetched")
        return "", 204

    pages = 0
    try:
        pages = len(PdfReader(io.BytesIO(body)).pages)
    except Exception:
        pass

    bucket().blob("received/%s.pdf" % fax_id).upload_from_string(
        body, content_type="application/pdf")
    bucket().blob("received/%s.json" % fax_id).upload_from_string(
        json.dumps({"fax_id": fax_id, "from": inner.get("from"),
                    "to": inner.get("to"), "pages": pages,
                    "received": datetime.datetime.now(
                        datetime.timezone.utc).isoformat()}),
        content_type="application/json")
    print("INBOUND FAX:", fax_id, inner.get("from"), "->", inner.get("to"),
          pages, "page(s)")
    return "", 204


@app.route("/received")
@requires_volunteer
def received_list():
    items = []
    for b in bucket().list_blobs(prefix="received/"):
        if b.name.endswith(".json"):
            try:
                items.append(json.loads(b.download_as_bytes()))
            except Exception:
                pass
    items.sort(key=lambda i: i.get("received") or "", reverse=True)
    return render_template("received.html", items=items)


@app.route("/received/<fax_id>.pdf")
@requires_volunteer
def received_pdf(fax_id):
    if not re.match(r"^[A-Za-z0-9_-]{1,64}$", fax_id):
        abort(404)
    blob = bucket().blob("received/%s.pdf" % fax_id)
    if not blob.exists():
        abort(404)
    return Response(blob.download_as_bytes(), mimetype="application/pdf")


def verify_telnyx(raw):
    """Ed25519 over "<telnyx-timestamp>|<raw body>", per Telnyx's scheme.

    The raw bytes matter: re-serialising the parsed JSON changes them and the
    signature stops matching.
    """
    if not TELNYX_PUBLIC_KEY:
        print("TELNYX_PUBLIC_KEY unset; refusing unverified webhook")
        return False
    sig = request.headers.get("telnyx-signature-ed25519") or ""
    ts = request.headers.get("telnyx-timestamp") or ""
    if not sig or not ts:
        return False
    try:
        if abs(int(datetime.datetime.now(datetime.timezone.utc).timestamp())
               - int(ts)) > 300:     # five minute replay window
            return False
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(TELNYX_PUBLIC_KEY))
        key.verify(base64.b64decode(sig), ts.encode() + b"|" + raw)
        return True
    except (InvalidSignature, ValueError, TypeError) as e:
        print("telnyx signature check failed:", type(e).__name__, e)
        return False


@app.route("/j/<job_id>")
def job_page(job_id):
    job = load_job(job_id)
    if not job:
        abort(404)
    return render_template("status.html", job=job,
                           host=PUBLIC_HOST or base_url().split("://", 1)[-1])


@app.route("/j/<job_id>.json")
def job_json(job_id):
    job = load_job(job_id)
    if not job:
        abort(404)
    return jsonify({"status": job.get("status"), "detail": job.get("detail"),
                    "pages": job.get("pages"), "to": job.get("to")})


if __name__ == "__main__":
    app.run(port=int(os.getenv("PORT") or 8080), debug=True)
