# syntax=docker/dockerfile:1.7
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

FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="AgentGuard" \
      org.opencontainers.image.description="Security & quality evaluation framework for AI agents" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN groupadd --system --gid 10001 agentguard \
 && useradd --system --uid 10001 --gid agentguard --home-dir /work --create-home agentguard
WORKDIR /work
COPY --from=builder --chown=agentguard:agentguard /opt/venv /opt/venv
COPY --chown=agentguard:agentguard datasets ./datasets
COPY --chown=agentguard:agentguard examples ./examples
RUN mkdir -p /work/.agentguard /work/reports && chown agentguard:agentguard /work/.agentguard /work/reports
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["agentguard"]
CMD ["--help"]
