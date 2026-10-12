# dafax — ballot fax relay

A voter standing at a tabling event scans their ballot on **their own phone**,
scans a QR code the volunteer shows them, and faxes it to their clerk
themselves. No account, no voter data stored, and the PDF is deleted the moment
Telnyx reports delivery or failure.

Deliberately separate from the phone-support app: different repo, different
platform, different account. Nothing here can take the voter helpline down.

## How it hangs together

```
volunteer  /mint          -> QR holding a single-use token (HTTP Basic)
voter      /s/<token>     -> upload form, destination, optional Turnstile
           POST /s/<token>-> normalise to a fax PDF, store in GCS, POST to Telnyx
Telnyx     GET  /m/<job>  -> fetches the PDF over an HMAC-signed, expiring URL
Telnyx     POST /telnyx   -> status events (Ed25519 verified); deletes the PDF
voter      /j/<job>       -> status page, polls /j/<job>.json
```

Tokens are signed (`itsdangerous`) and burned exactly once by creating a GCS
object with `if_generation_match=0`, so two phones racing the same QR code
cannot both send. No database anywhere — job records are small JSON objects in
the bucket, and the daily page cap is summed from object metadata in a listing.

What is kept after a fax: destination, page count, status, which volunteer
minted the token. No image, no name, no address.

## Deploy

### 1. gcloud

```sh
brew install --cask google-cloud-sdk
gcloud auth login
gcloud config set project YOUR_PROJECT
gcloud services enable run.googleapis.com cloudbuild.googleapis.com storage.googleapis.com
```

### 2. Bucket

Note the lifecycle rule: it is the backstop that guarantees a ballot cannot
linger if a Telnyx webhook never arrives.

```sh
gcloud storage buckets create gs://YOUR_BUCKET \
  --location=us-central1 --uniform-bucket-level-access --public-access-prevention

printf '{"rule":[{"action":{"type":"Delete"},"condition":{"age":1}}]}' > /tmp/lc.json
gcloud storage buckets update gs://YOUR_BUCKET --lifecycle-file=/tmp/lc.json
```

### 3. Service account

```sh
gcloud iam service-accounts create dafax --display-name="ballot fax relay"
SA=dafax@YOUR_PROJECT.iam.gserviceaccount.com
gcloud storage buckets add-iam-policy-binding gs://YOUR_BUCKET \
  --member="serviceAccount:$SA" --role=roles/storage.objectAdmin
```

### 4. Telnyx

In Mission Control, in this order:

1. Create a **Programmable Fax application**. Its webhook goes to
   `https://<your-run-url>/telnyx` — fill that in after the first deploy.
2. Create an **Outbound Voice Profile** and **assign it to that application**.
   Outbound faxes are refused without one, and this is the single most common
   reason a first send fails.
3. Buy **two fax-capable numbers** and assign both to the application. One is
   what you send from (`TELNYX_FROM`); the second is only there so you can fax
   yourself (see Testing).
4. Collect the **API key**, and the account **public key** from Account
   Settings → Keys & Credentials.

`TELNYX_CONNECTION_ID` is the **application's** id, not a number's.

Keep the balance low and auto-recharge **off**. That is the hard ceiling on
what any abuse can cost.

### Testing without a real clerk

Both numbers sit on the same application, so an inbound fax arrives at the same
`/telnyx` webhook as a status event and gets stored. Send from number one to
number two, then open `/received` (volunteer login) and read the PDF that
actually came out the far end.

Do this before faxing any clerk. It is the only honest check that a ballot is
still legible after passing through 1-bit 204 dpi, and legibility is the most
likely thing to be wrong. `/received` is a test rig, not storage: the bucket's
one-day lifecycle rule clears it, and only numbers you own should point at it.

### 5. Deploy

`us-central1` matters — the always-free tier only applies in `us-central1`,
`us-east1` and `us-west1`.

```sh
cp .env.example .env.yaml   # convert to YAML key: value, fill in real values
gcloud run deploy dafax \
  --source . --region us-central1 --allow-unauthenticated \
  --service-account "$SA" \
  --memory 512Mi --cpu 1 --concurrency 8 --max-instances 3 \
  --env-vars-file .env.yaml
```

Then set `BASE_URL` to the URL it prints and redeploy, and point the Telnyx
application's webhook at `<that URL>/telnyx`.

Finally, cap the downside: a billing budget alert on the project, and
`--max-instances 3` above, so neither traffic nor a bug can quietly run up a
bill on a free-tier account.

## Local

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
set -a && . ./.env && set +a
.venv/bin/python app.py
```

Telnyx has to reach you for the media fetch and the webhook, so tunnel it and
set `BASE_URL` to the tunnel hostname:

```sh
cloudflared tunnel --url http://localhost:8080
```

## Deliberately not built

- **No destination allowlist.** Any US or Canadian geographic number is
  accepted (premium 900/976 ranges and our own number are refused). The
  volunteer-issued token, the page caps and the Telnyx balance are what stand
  between this and being an open fax relay. An allowlist of election-office
  numbers would be the strongest single control if this ever gets abused.
- **Turnstile is optional.** Leave `TURNSTILE_SECRET` blank and the check is
  skipped; set it if the token alone proves insufficient.
- **No retries.** A clerk's fax line is often busy, especially near a
  deadline. Right now the voter sees "did not go through" and the volunteer
  has to mint a new code. Automatic retry is the first thing to add.
