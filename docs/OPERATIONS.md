# Running and managing the app

## Choosing a model

Mode **Live AI** uses whichever provider you configure. **Demo** needs none, and its decisions are scripted.

| Provider | Start with | Notes |
|---|---|---|
| Claude API | `read -s ANTHROPIC_API_KEY && export ANTHROPIC_API_KEY` then `./dev.sh` | Uses `claude-opus-5-5` |
| Gemini API | `read -s GEMINI_API_KEY && export GEMINI_API_KEY` then `LLM_PROVIDER=gemini ./dev.sh` | Uses `gemini-3.8-flash`, or set `GEMINI_MODEL` |
| Your Claude Code login | `LLM_PROVIDER=claude_code CLAUDE_CODE_OWNER=<username> ./dev.sh` | Personal local testing only. Only that user can start live runs, and production refuses it |

Each run is capped at about $1 and each day at about $20 by the app's own estimate. Change these with `RUN_BUDGET_USD` and `DAILY_BUDGET_USD`, and set a spending limit with your provider too.

## People and roles

Admins invite people from the **Users** page. Each person sets a password and sets up an authenticator app, and MFA is required at every login.

| Action | `viewer` | `researcher` | `tier1` | `tier2` | `admin` |
|---|---|---|---|---|---|
| See alerts, runs and traces | ✅ | ✅ | ✅ | ✅ | ✅ |
| Use the dashboard | | ✅ | ✅ | ✅ | ✅ |
| Simulate alerts | | ✅ | ✅ | ✅ | ✅ |
| Start investigations | | ✅ | ✅ | ✅ | |
| Approve or deny containment | | | ✅ | ✅ | |
| Flush the cache | | | | ✅ | ✅ |
| Manage users | | | | | ✅ |

From the command line:

```bash
.venv/bin/python -m app.auth set-user <username> <role>   # create a user, or change their role and password
.venv/bin/python -m app.auth list-users
.venv/bin/python -m app.auth remove-user <username>
.venv/bin/python -m app.auth reset-mfa <username>         # for a lost device
```

**Back up `.mfa.key`.** It encrypts everyone's MFA secrets and is never committed. If it's lost, every user's MFA has to be reset.

## Metrics

`/metrics` serves Prometheus metrics, and accepts only a service token, never a login.

```bash
.venv/bin/python -m app.auth create-token prometheus      # shown once
curl -H "Authorization: Bearer $METRICS_TOKEN" http://localhost:8000/metrics
.venv/bin/python -m app.auth revoke-token prometheus
```

## Simulated alerts

Click **Simulate** on the Investigate page, or stream them with `ALERT_EVERY_SECONDS=60 ./dev.sh`. Simulated log events pass through detection rules in `app/alerts.py`, and some incidents are benign. Alerts wait for a person to start a run, so they never use model credits by themselves.

## Running the pieces separately

```bash
.venv/bin/python -m app.broker
.venv/bin/uvicorn app.server:app --port 8000
.venv/bin/python -m app.worker --id worker-1 --concurrency 2
```

To deploy on a server with HTTPS, see [DEPLOY.md](../DEPLOY.md).
