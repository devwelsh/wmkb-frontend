FROM python:3.12-slim

LABEL maintainer="viibeware"
LABEL description="WMKB Frontend — public-facing Knowledge Base for Warehouse Manager"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY app.py wm_client.py sync.py CHANGELOG.md ./
COPY templates/ templates/
COPY static/ static/
COPY entrypoint.sh /entrypoint.sh

# The app runs as an unprivileged user; the entrypoint (root) only chowns /data
# for volumes created by older root-running images, then drops to wmkb.
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin wmkb \
    && mkdir -p /data/cache /data/branding \
    && chown -R wmkb:wmkb /data \
    && chmod +x /entrypoint.sh

ENV WMKB_DATA_DIR=/data
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]

# 2 web workers is plenty for a read-mostly cached mirror behind a reverse
# proxy; the scheduled sync runs in the separate `wmkb-sync` service.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]
