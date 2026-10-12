FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Cloud Run sets PORT. Threads, not workers: every request here is I/O bound
# (GCS, Telnyx) apart from the image conversion, and one worker keeps the
# memory footprint inside the free tier.
ENV PORT=8080
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 120 app:app
