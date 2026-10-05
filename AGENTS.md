# AGENTS.md

AWG Panel — Russian-language web panel for managing native AmneziaWG VPN servers. Runs
without Docker: it edits `/etc/amnezia/amneziawg/awg0.conf` and applies changes via
`awg syncconf`. Panels and agents are separate FastAPI apps that share `core.py`.

## Layout
- `core.py` — all AmneziaWG logic shared by both apps: config parse/rewrite, `awg`/`awg-quick` commands, apt install/upgrade of AmneziaWG, client state. State/config paths are resolved from env at import time.
- `stats.py` — traffic/connection statistics: SQLite store (`buckets` hourly, `peers` monotonic totals, `events` reboots), `sampler_worker()` (runs in both apps' lifespan), `report()`. Stdlib only, no new deps.
- `app.py` — panel on `:5182`. Basic-auth UI + JSON API, proxies client ops to agents over HTTP with `X-Api-Key`, owns the background tasks (agent deploy, panel self-update, awg update). `/api/stats` serves the local DB or merges agent reports for `server=all`.
- `agent.py` — per-VDS agent on `:5183`. Bearer-token auth (`X-Api-Key`, `hmac.compare_digest`), background apt-refresh loop.
- `deployer.py` — installs the agent on a fresh VDS via paramiko/SFTP; pins SSH host keys (TOFU) in `/etc/awg-panel/known-hosts.json`.
- `updater.py` + `deploy/upgrade-panel.sh` — panel self-update from GitHub Releases (SHA-256 check, MANIFEST-driven in-place swap, pip reinstall, rollback).
- `templates/index.html` — single-file UI, no frontend build step. All user-facing strings/progress messages are Russian; don't translate them.

## No tests, no linters
There is no test suite, formatter, or type checker. The only verification the repo performs is compile/import (release pipeline runs `import app` too). `venv` is Python 3.12.
```bash
venv/bin/python -m py_compile app.py agent.py core.py stats.py updater.py deployer.py
venv/bin/python -c "import app, agent, updater, deployer, core, stats"
```

## Local dev
Real AWG ops need root and `/etc/amnezia/amneziawg`; core.py reads those paths at import time, so set env before starting uvicorn.
```bash
# panel — fail-closed: without a password everything returns 503 (or set AWG_ALLOW_NO_AUTH=1)
AWG_PANEL_PASSWORD=devpass venv/bin/uvicorn app:app --port 5182
# agent — non-root test mode: point config/state at a temp dir
AWG_AGENT_TOKEN=testtoken AWG_CONFIG_DIR=/tmp/awg-test venv/bin/uvicorn agent:app --port 5183
```
Gotchas:
- The panel SSRF guard rejects agent URLs on loopback/private/etc. IPs. To test a local agent, start the panel with `AWG_ALLOW_PRIVATE_AGENTS=1`.
- `state.json` / `servers.json` / `stats.db*` are gitignored runtime data (someone's clients, agent creds, traffic history) — never commit or put them in a release bundle.
- AWG counters reset on reboot and on peer re-creation, so `stats.py` stores *deltas* plus monotonic totals and a `boot_id` change; don't derive "traffic for a period" from current counters.

## Release / self-update
- `VERSION` is the single source of truth (keep `v<version>` tag in sync). Tagging `v*` triggers `.github/workflows/release.yml` → `bash deploy/build-release.sh`, which packages for GitHub Releases.
- `deploy/build-release.sh` copies an explicit file list into the bundle. If you add a new top-level production file, add it there (repo-root `MANIFEST` is a gitignored generated artifact, not hand-edited).
- `deploy/upgrade-panel.sh` refuses any bundle whose MANIFEST touches protected paths (`.git/`, `venv/`, `.updates/`, `__pycache__/`, etc.) or user data. `updater.py` also enforces `_PAYLOAD_REQUIRED` core files. Never add the panel's own runtime state to a release.
- After changing code paths, keep `updater.py`'s swap/rollback contract intact: `deploy/upgrade-panel.sh <marker.json>` is the only mechanism that updates a live install.