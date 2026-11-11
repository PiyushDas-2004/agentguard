# syntax=docker/dockerfile:1.7
# Public demo of the AgentGuard dashboard, pre-seeded at build time with real offline runs of the
# bundled demo agents (vulnerable, partially hardened, RAG, hardened). Listens on $PORT (default 8000).
#   docker build -f deploy/demo.Dockerfile -t agentguard-demo .
#   docker run -p 8000:8000 agentguard-demo
FROM python:3.12-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/opt/venv
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
COPY datasets ./datasets
# Optional corporate/proxy CA bundle: docker build --secret id=ca_bundle,src=/path/ca.crt .
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -s /run/secrets/ca_bundle ]; then export SSL_CERT_FILE=/run/secrets/ca_bundle; fi; \
    uv sync --locked --no-dev --extra dashboard --no-editable

FROM python:3.12-slim AS demo
LABEL org.opencontainers.image.title="AgentGuard demo dashboard" \
      org.opencontainers.image.source="https://github.com/PiyushDas-2004/agentguard" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN groupadd --system --gid 10001 agentguard \
 && useradd --system --uid 10001 --gid agentguard --home-dir /work --create-home agentguard
WORKDIR /work
COPY --from=builder --chown=agentguard:agentguard /opt/venv /opt/venv
COPY --chown=agentguard:agentguard datasets ./datasets
COPY --chown=agentguard:agentguard examples ./examples
COPY --chown=agentguard:agentguard deploy/seed_demo.sh ./seed_demo.sh
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 AGENTGUARD_HOST=0.0.0.0 PORT=8000 \
    AGENTGUARD_BANNER="Live demo: real offline AgentGuard runs (2 trials per case) of the bundled demo agents. The vulnerable and partially hardened agents fail by design; the hardened agent wraps the same naive model in defense code. Source: github.com/PiyushDas-2004/agentguard"
USER 10001:10001
RUN ./seed_demo.sh
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD ["python", "-c", "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8000'), timeout=2).status == 200 else 1)"]
CMD ["agentguard", "dashboard"]
