FROM python:3.12-slim

LABEL maintainer="viibeware"
LABEL description="WMKB Frontend — public-facing Knowledge Base for Warehouse Manager"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py wm_client.py sync.py CHANGELOG.md ./
COPY templates/ templates/
COPY static/ static/

RUN mkdir -p /data/cache /data/branding

ENV WMKB_DATA_DIR=/data
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

# 2 web workers is plenty for a read-mostly cached mirror behind a reverse
# proxy; the scheduled sync runs in the separate `wmkb-sync` service.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]
