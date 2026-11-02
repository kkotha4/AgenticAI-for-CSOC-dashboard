#!/usr/bin/env bash
# Copy only what a deployment needs to a server, for testing before the code is on GitHub.
#   scripts/sync_to_server.sh user@server [--dry-run]
# An allowlist: anything not named here, such as local data and secrets, is never copied.
set -euo pipefail
target="${1:?Usage: scripts/sync_to_server.sh user@server [--dry-run]}"
cd "$(dirname "$0")/.."
rsync -az --delete ${2:-} \
  --exclude='__pycache__/' --exclude='*.pyc' --exclude='.DS_Store' \
  --include='/app/***' --include='/static/***' \
  --include='/Dockerfile' --include='/docker-compose.yml' --include='/Caddyfile' --include='/.dockerignore' \
  --include='/requirements.lock' --include='/.env.example' --include='/DEPLOY.md' --include='/LICENSE' \
  --exclude='*' \
  ./ "$target:soc-triage-agent/"
