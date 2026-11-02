#!/usr/bin/env bash
# Start the broker, two workers and the web server. Ctrl+C stops all of them.
cd "$(dirname "$0")"
trap 'kill 0' EXIT
.venv/bin/python -m app.broker &
sleep 0.5
.venv/bin/python -m app.worker --id worker-1 --concurrency 2 &
.venv/bin/python -m app.worker --id worker-2 --concurrency 2 &
if [ -n "$ALERT_EVERY_SECONDS" ]; then   # optional: a steady stream of new alerts
  .venv/bin/python -m app.alertgen --every "$ALERT_EVERY_SECONDS" &
fi
.venv/bin/uvicorn app.server:app --port "${PORT:-8000}"
