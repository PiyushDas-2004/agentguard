# Deployment and hosting

AgentGuard is a CLI, a read-only results **dashboard**, and a hosted multi-user **web app**
(`agentguard serve`). This page covers all of them; the web app is the one to deploy for other people.

## 0. Hosted web app — Render (recommended for other users)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/PiyushDas-2004/agentguard)

`render.yaml` creates a Docker web service from `deploy/web.Dockerfile` and a managed Postgres
database. Render generates `AGENTGUARD_SECRET_KEY` and `AGENTGUARD_SIGNUP_CODE`; the public URL
(`RENDER_EXTERNAL_URL`) becomes the base URL automatically.

1. Click the button, sign in to Render, approve the blueprint (a web service + a database).
2. When the deploy is live, open the service → **Environment** and copy `AGENTGUARD_SIGNUP_CODE`.
   Share it with the people who should be able to create accounts (or set
   `AGENTGUARD_OPEN_SIGNUP=true` to let anyone sign up).
3. Open the service URL, create an account with the invite code, add your agent's endpoint,
   verify ownership, and run a scan.

**LLM access.** Verdicts come from deterministic detectors, so scans work without any LLM key.
For ambiguous jailbreak cases users can add a Gemini LLM judge with **their own** Gemini API key
(created at https://aistudio.google.com/apikey). The key is sent to Google only, kept in memory
for that one scan and never stored. The operator does not need a key.

**Free plan notes.** Free Render web services sleep after inactivity (first request takes ~1 min)
and free Postgres databases expire after 30 days unless upgraded. Upgrade both for real use.

### Web app environment variables

| Variable | Default | Meaning |
|---|---|---|
| `AGENTGUARD_ENV` | `production` in the image | `production` enforces the guards below |
| `AGENTGUARD_SECRET_KEY` | — (required, ≥32 chars) | server secret |
| `AGENTGUARD_BASE_URL` | `RENDER_EXTERNAL_URL` | public `https://` URL (CSRF origin check, cookies) |
| `AGENTGUARD_SIGNUP_CODE` | — | invite code required to sign up (≥12 chars) |
| `AGENTGUARD_OPEN_SIGNUP` | `false` | allow sign-up without a code |
| `DATABASE_URL` | `sqlite:///.agentguard/web.db` | Postgres (`postgres://…`) or SQLite |
| `AGENTGUARD_TRUSTED_PROXY_HOPS` | `1` | reverse proxies appending to `X-Forwarded-For` |
| `AGENTGUARD_MAX_CONCURRENT_SCANS` | `2` | scans running at once |
| `AGENTGUARD_MAX_QUEUED_SCANS` | `20` | queue size |
| `AGENTGUARD_SCANS_PER_USER_PER_DAY` | `20` | per-user quota |
| `AGENTGUARD_MAX_TRIALS` | `3` | max trials per case |
| `AGENTGUARD_TARGET_RPS` | `2` | requests per second sent to a target |
| `AGENTGUARD_RETENTION_DAYS` | `30` | scans and audit events older than this are deleted (hourly) |
| `AGENTGUARD_MAX_SCAN_MINUTES` | `30` | total time limit per scan |
| `AGENTGUARD_SESSION_HOURS` | `12` | session lifetime |

The security design is described in [HOSTED_SECURITY.md](HOSTED_SECURITY.md). Run one instance
only (in-memory queue and rate limiter; secrets are never persisted).

Elsewhere: `docker run -p 8000:8000 -e AGENTGUARD_SECRET_KEY=... -e AGENTGUARD_SIGNUP_CODE=...
-e AGENTGUARD_BASE_URL=https://your.domain -e DATABASE_URL=postgres://... ghcr.io/piyushdas-2004/agentguard-web`
behind a TLS-terminating proxy.

## 1. Static site — GitHub Pages (landing page + sample reports)

`.github/workflows/pages.yml` runs `scripts/build_site.py` on every push to `main` and publishes
`_site/` to the `gh-pages` branch. Pages serves it at
**https://piyushdas-2004.github.io/agentguard/**.

One-time setting, if the site is not live: *Settings → Pages → Build and deployment → Source:
"Deploy from a branch" → Branch: `gh-pages` / `(root)` → Save.*

## 2. Container images — GitHub Container Registry

`.github/workflows/publish.yml` builds and pushes on every push to `main` and on `v*` tags:

| Image | Contents |
|---|---|
| `ghcr.io/piyushdas-2004/agentguard` | the CLI (`docker run ghcr.io/piyushdas-2004/agentguard run -c ...`) |
| `ghcr.io/piyushdas-2004/agentguard-demo` | the dashboard, pre-seeded at build time with real offline runs of the four demo agents |
| `ghcr.io/piyushdas-2004/agentguard-web` | the hosted multi-user web app (`agentguard serve`) |

```bash
docker run -p 8000:8000 ghcr.io/piyushdas-2004/agentguard-demo:latest   # http://localhost:8000
```

New GHCR packages may start as *private*. To allow anonymous pulls: GitHub → your profile →
Packages → `agentguard-demo` → Package settings → Change visibility → Public.

## 3. Read-only demo dashboard on any container host

The demo dashboard image (no accounts, synthetic demo data only) runs on any container host that sets `$PORT` (Fly.io, Railway, Google Cloud Run,
Azure Container Apps, Hugging Face Docker Spaces):

| Setting | Value |
|---|---|
| Dockerfile | `deploy/demo.Dockerfile` (build context: repository root) |
| Port | `$PORT` (default 8000) |
| Health check | `GET /healthz` → `{"status":"ok"}` |

## Environment variables (dashboard)

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8000` | listen port |
| `AGENTGUARD_HOST` | `127.0.0.1` (`0.0.0.0` in the images) | bind address |
| `AGENTGUARD_DB` | `.agentguard/agentguard.db` | results database |
| `AGENTGUARD_BANNER` | unset | note shown above the runs list (used by the public demo) |

## Security notes

* The dashboard is read-only and has no authentication. The demo image contains only synthetic
  demo data; do **not** expose a dashboard that holds results for your production agents without
  putting it behind authentication (reverse proxy, VPN, Cloud Run IAM, ...).
* Reports contain your agent's system prompt and tool traces — treat them as sensitive.
* Containers run as an unprivileged user (uid 10001).
