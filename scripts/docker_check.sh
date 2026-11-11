#!/usr/bin/env bash
# Docker gate.
#
# With a Docker daemon: build the image, run an offline smoke evaluation inside it, start the
# dashboard with `docker compose`, wait until /healthz answers {"status":"ok"} and tear it down.
# Without a daemon: lint the Dockerfile with hadolint (binary, or nothing) and say so explicitly.
#
# Env:
#   AG_CA_BUNDLE   CA bundle passed as the optional `ca_bundle` build secret
#                  (default: /root/.ccr/ca-bundle.crt when that file exists)
#   AG_IMAGE       image tag (default agentguard:local, the tag docker-compose.yml uses)
#   AG_HEALTH_PORT host port of the dashboard (default 8000, as in docker-compose.yml)
set -euo pipefail

cd "$(dirname "$0")/.."
IMAGE="${AG_IMAGE:-agentguard:local}"
PORT="${AG_HEALTH_PORT:-8000}"
if [[ -z "${AG_CA_BUNDLE:-}" && -f /root/.ccr/ca-bundle.crt ]]; then
  AG_CA_BUNDLE=/root/.ccr/ca-bundle.crt
fi

hadolint_check() {
  if command -v hadolint >/dev/null 2>&1; then
    echo "docker_check: running hadolint $(hadolint --version 2>/dev/null | head -1)"
    hadolint Dockerfile
    echo "docker_check: hadolint passed (image was NOT built: no Docker daemon)"
    return 0
  fi
  echo "docker_check: FAIL — no Docker daemon and no hadolint binary; nothing was verified" >&2
  return 1
}

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "docker_check: no Docker daemon available — falling back to hadolint"
  hadolint_check
  exit $?
fi

echo "docker_check: Docker daemon available ($(docker version --format '{{.Server.Version}}' 2>/dev/null))"

# 1. Lint (hadolint via its pinned image, same rules and threshold as CI) — fatal on any finding.
HADOLINT_IMAGE=ghcr.io/hadolint/hadolint:v2.15.1
if docker image inspect "$HADOLINT_IMAGE" >/dev/null 2>&1 || docker pull -q "$HADOLINT_IMAGE" >/dev/null 2>&1; then
  for dockerfile in Dockerfile deploy/demo.Dockerfile; do
    echo "docker_check: hadolint ($HADOLINT_IMAGE, threshold=info) on $dockerfile"
    docker run --rm -i -e HADOLINT_FAILURE_THRESHOLD=info "$HADOLINT_IMAGE" < "$dockerfile"
  done
  echo "docker_check: hadolint passed"
else
  echo "docker_check: hadolint image unavailable — lint skipped (build still runs)"
fi

# 2. Build.
build_args=(-t "$IMAGE")
if [[ -n "${AG_CA_BUNDLE:-}" && -f "$AG_CA_BUNDLE" ]]; then
  echo "docker_check: passing CA bundle $AG_CA_BUNDLE as build secret ca_bundle"
  build_args+=(--secret "id=ca_bundle,src=$AG_CA_BUNDLE")
fi
echo "docker_check: docker build ${build_args[*]} ."
DOCKER_BUILDKIT=1 docker build "${build_args[@]}" .
docker image inspect "$IMAGE" --format 'docker_check: image {{.Id}} size {{.Size}} bytes user {{.Config.User}}'

# 3. Offline smoke evaluation inside the container (exit 1 = vulnerable demo agent flagged).
echo "docker_check: offline smoke run inside the container"
set +e
docker run --rm "$IMAGE" run -c examples/demo.yaml --offline --quiet --suite security \
  --category PI_DIRECT --trials 1 --out-dir /tmp/reports >/tmp/agentguard-docker-run.log 2>&1
code=$?
set -e
tail -3 /tmp/agentguard-docker-run.log
if [[ $code -ne 1 ]]; then
  echo "docker_check: FAIL — expected exit 1 (risk above threshold) from the vulnerable demo, got $code" >&2
  cat /tmp/agentguard-docker-run.log >&2
  exit 1
fi
echo "docker_check: smoke run exited 1 as expected (vulnerable demo flagged)"

# 4. docker compose: dashboard healthy and /healthz answers.
cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
echo "docker_check: docker compose up -d --no-build dashboard"
docker compose up -d --no-build dashboard
status=""
for _ in $(seq 1 60); do
  cid="$(docker compose ps -q dashboard)"
  status="$(docker inspect --format '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo unknown)"
  [[ "$status" == "healthy" ]] && break
  sleep 2
done
if [[ "$status" != "healthy" ]]; then
  echo "docker_check: FAIL — dashboard container status '$status' (not healthy)" >&2
  docker compose logs dashboard >&2 || true
  exit 1
fi
body="$(curl -fsS --noproxy '*' "http://127.0.0.1:${PORT}/healthz")"
echo "docker_check: GET /healthz -> $body"
if [[ "$body" != *'"status":"ok"'* ]]; then
  echo "docker_check: FAIL — unexpected /healthz body" >&2
  exit 1
fi
echo "docker_check: PASS (hadolint, build, offline smoke run, compose healthcheck, /healthz)"
