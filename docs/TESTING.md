# Testing and CI/CD

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python scripts/run_tests.py unit        # one function at a time, about a second
.venv/bin/python scripts/run_tests.py component   # real server, worker and broker, with fake models
.venv/bin/python scripts/run_tests.py e2e         # the whole journey in real Chrome
```

No level calls a real model or touches local data: each uses a temporary database and its own ports.

## The pipeline

`.github/workflows/ci.yml` runs on every push to `main` or `release/**`, and on pull requests:

1. **Unit:** the unit tests, and a check of dependencies for known vulnerabilities
2. **Component** and **Browser**, side by side
3. **Container:** builds the real image, starts the whole stack over HTTPS, and checks security headers, access controls, non-root users, key separation and backups

A version tag such as `v1.0.0` also publishes an image and a GitHub release, only if everything passes. Nothing in the pipeline deploys to a server.

## Re-recording the demo

```bash
.venv/bin/python scripts/record_demo.py docs/demo <temporary folder>     # macOS, needs Chrome
python scripts/encode_demo.py <temporary folder> docs/demo <path to ffmpeg>
```

It uses Demo mode, simulated data and a made-up account on a temporary server.
