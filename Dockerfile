# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv sync --locked --no-dev --extra dashboard --no-editable

FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="AgentGuard" \
      org.opencontainers.image.description="Security & quality evaluation framework for AI agents" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN groupadd --system --gid 10001 agentguard \
 && useradd --system --uid 10001 --gid agentguard --home-dir /work --create-home agentguard
WORKDIR /work
COPY --from=builder --chown=agentguard:agentguard /app/.venv /opt/venv
COPY --chown=agentguard:agentguard datasets ./datasets
COPY --chown=agentguard:agentguard examples ./examples
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1
USER agentguard
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["agentguard"]
CMD ["--help"]
