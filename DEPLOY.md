# Deploying SOC Triage Agent

This runs the whole app on one Linux server with HTTPS. It's sized for a small team or a client pilot.

**Before you start:** the data here is simulated, and containment actions don't touch real systems. Connecting real log sources or firewalls needs its own security review.

## What you need

- A Linux server with at least 2 GB of memory, with Docker and the Compose plugin installed
- A domain name pointing at that server
- A firewall allowing only ports 22, 80 and 443
- A model API key, if you want Live mode. `claude_code` is for one person's local testing and is refused in production

## 1. Configure

```bash
git clone <your repo> soc-triage-agent && cd soc-triage-agent   # or, before it is on GitHub, run scripts/sync_to_server.sh on your own computer
cp .env.example .env
nano .env              # set DOMAIN, and optionally LLM_PROVIDER and its API key
chmod 600 .env
```

## 2. Create the MFA encryption key

This encrypts everyone's MFA secrets. **Save a copy in your password manager.** If it's lost, every user's MFA has to be reset.

```bash
mkdir -p secrets
head -c 32 /dev/urandom > secrets/mfa.key
sudo chown 10001 secrets/mfa.key   # the user the app runs as
sudo chmod 400 secrets/mfa.key
```

## 3. Start it

```bash
docker compose up -d --build
docker compose ps
curl https://YOUR_DOMAIN/readyz    # should print {"status":"ok"}
```

Caddy gets an HTTPS certificate automatically. If a setting is unsafe, the app refuses to start and says why: see `docker compose logs web`.

## 4. Create the first admin

Production has no default accounts.

```bash
docker compose exec web python -m app.auth set-user admin admin
```

Log in at `https://YOUR_DOMAIN` and set up MFA. Invite everyone else from the **Users** page.

## Day to day

| Task | Command |
|---|---|
| See what's running | `docker compose ps` |
| Read logs | `docker compose logs -f web worker` |
| Update to new code | `git pull && docker compose up -d --build` |
| Add simulated alerts | `docker compose --profile demo up -d` |
| Create a metrics token | `docker compose exec web python -m app.auth create-token prometheus` |
| Reset MFA if no admin can log in | `docker compose exec web python -m app.auth reset-mfa <username>` |

Run more workers with `docker compose up -d --scale worker=4`.

## Backups

Schedule this daily with cron:

```bash
docker compose exec -T web python -m app.backup --keep 14
```

Backups go to `/data/backups` on the data volume, so **copy them off the server**: a backup on the same disk doesn't survive losing that disk. They contain password hashes and encrypted MFA secrets, so treat them as sensitive.

To restore:

```bash
docker compose stop web worker alert-stream
docker compose run --rm --no-deps --entrypoint sh web -c 'cp /data/backups/soc-YYYYMMDD-HHMMSS.db /data/soc.db && rm -f /data/soc.db-wal /data/soc.db-shm'
docker compose up -d
```

Test a restore before you need one.

## Rotating secrets

- **Model API key:** create a new one, update `.env`, then run `docker compose up -d worker`. Revoke the old key.
- **Metrics token:** create a second token, switch the scraper to it, then revoke the first with `revoke-token`.
- **MFA key:** there's no automatic rotation yet. Replacing it means resetting everyone's MFA.

## Known limits

- **One server:** SQLite works across these containers because they share a local disk. To run on several servers, or for high availability, move to managed Postgres first. Don't put SQLite on a network file system.
- **One organization per deployment:** there's no separation between clients inside one database. For several clients, run a separate deployment for each, with its own data, keys and domain.
- **Alerts don't page anyone:** they appear on the dashboard. Connect Prometheus and an alert manager to get notified.
- **Local accounts:** enterprises will usually want SSO instead.
