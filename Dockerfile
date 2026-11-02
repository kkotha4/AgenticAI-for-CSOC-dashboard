# One image runs the web server, workers and broker. Compose chooses the command.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

# Exact versions from the lock file, so every build runs the same dependencies.
COPY requirements.lock /tmp/requirements.lock
RUN pip install -r /tmp/requirements.lock && rm /tmp/requirements.lock

# Only the code the app needs. Tests, demo media and local data stay out of the image.
WORKDIR /srv/app
COPY app ./app
COPY static ./static

# Run as an unprivileged user that owns only the data folder.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin soc \
 && mkdir -p /data/logs /data/backups && chown -R soc:soc /data
USER soc

ENV APP_ENV=production SOC_DB_PATH=/data/soc.db SOC_AUDIT_PATH=/data/audit.jsonl SOC_LOG_DIR=/data/logs SOC_BACKUP_DIR=/data/backups
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"
CMD ["python", "-m", "uvicorn", "app.server:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
