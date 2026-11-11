# syntax=docker/dockerfile:1.7
# Hosted multi-user AgentGuard web app (see docs/DEPLOYMENT.md and docs/HOSTED_SECURITY.md).
FROM python:3.15-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/opt/venv
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
COPY datasets ./datasets
RUN --mount=type=secret,id=ca_bundle,required=false \
    if [ -s /run/secrets/ca_bundle ]; then export SSL_CERT_FILE=/run/secrets/ca_bundle; fi; \
    uv sync --locked --no-dev --extra web --no-editable

FROM python:3.15-slim AS runtime
LABEL org.opencontainers.image.title="AgentGuard web" \
      org.opencontainers.image.description="Hosted AgentGuard: red-team your AI agent from the browser" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN groupadd --system --gid 10001 agentguard \
 && useradd --system --uid 10001 --gid agentguard --home-dir /work --create-home agentguard
WORKDIR /work
COPY --from=builder --chown=root:root /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    AGENTGUARD_HOST=0.0.0.0 AGENTGUARD_ENV=production
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD ["python", "-c", "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT', '8000'), timeout=2).status == 200 else 1)"]
ENTRYPOINT ["agentguard"]
CMD ["serve"]
