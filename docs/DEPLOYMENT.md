# Deployment and hosting

AgentGuard is a CLI plus a read-only results **dashboard**. There are three ways to host it.

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

```bash
docker run -p 8000:8000 ghcr.io/piyushdas-2004/agentguard-demo:latest   # http://localhost:8000
```

New GHCR packages may start as *private*. To allow anonymous pulls: GitHub → your profile →
Packages → `agentguard-demo` → Package settings → Change visibility → Public.

## 3. Live dashboard — Render (one click)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/PiyushDas-2004/agentguard)

`render.yaml` defines a free Docker web service built from `deploy/demo.Dockerfile`, with
`/healthz` as the health check. The button asks you to sign in to Render, shows the blueprint,
and deploys. Subsequent pushes to `main` redeploy automatically.

The same image runs on any container host that sets `$PORT` (Fly.io, Railway, Google Cloud Run,
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
