#!/usr/bin/env bash
# Run every AgentGuard quality gate. Exits non-zero if any gate fails.
#
# Usage:
#   scripts/check_all.sh            # all gates
#   scripts/check_all.sh --fast     # skip slow gates (mutation testing, load test, docker, fresh clone)
#   GATES="lint types" scripts/check_all.sh   # run a named subset
set -uo pipefail

cd "$(dirname "$0")/.."
export UV_SYSTEM_CERTS=1
unset UV_NATIVE_TLS || true

FAST=0
for arg in "$@"; do
  case "$arg" in
    --fast) FAST=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

ALL_GATES="lint format types tests coverage bandit audit secrets docstrings datasets metavalidate determinism mutation load docker freshclone"
SLOW_GATES="mutation load docker freshclone"
GATES="${GATES:-$ALL_GATES}"

declare -a PASSED=()
declare -a FAILED=()
declare -a SKIPPED=()

run_gate() {
  local name="$1"; shift
  if [[ " $GATES " != *" $name "* ]]; then return 0; fi
  if [[ $FAST -eq 1 && " $SLOW_GATES " == *" $name "* ]]; then SKIPPED+=("$name"); return 0; fi
  echo
  echo "================ gate: $name ================"
  if "$@"; then PASSED+=("$name"); else FAILED+=("$name"); fi
}

gate_lint()        { uv run ruff check .; }
gate_format()      { uv run ruff format --check .; }
gate_types()       { uv run mypy --strict src/; }
gate_tests()       {
  uv run pytest -m "not live" --disable-socket --allow-unix-socket --allow-hosts=127.0.0.1,localhost \
    -q -p no:cacheprovider --cov=agentguard --cov-report=term --cov-report=xml:coverage.xml
}
gate_coverage()    { uv run python scripts/coverage_gate.py coverage.xml; }
gate_bandit()      { uv run bandit -q -r src/ -ll; }
gate_audit()       { uv run python scripts/run_pip_audit.py; }
gate_secrets()     { uv run python scripts/secret_scan.py; }
gate_docstrings()  { uv run interrogate -c pyproject.toml src/agentguard; }
gate_datasets()    { uv run agentguard lint-datasets; }
gate_metavalidate(){ uv run agentguard meta-validate --out docs/meta_validation.json; }
gate_determinism() { uv run python scripts/determinism_check.py; }
gate_mutation()    { uv run python scripts/mutation_gate.py; }
gate_load()        { uv run python scripts/load_test.py --trials 1000 --concurrency 32; }
gate_docker()      { scripts/docker_check.sh; }
gate_freshclone()  { scripts/fresh_clone_check.sh; }

run_gate lint gate_lint
run_gate format gate_format
run_gate types gate_types
run_gate tests gate_tests
run_gate coverage gate_coverage
run_gate bandit gate_bandit
run_gate audit gate_audit
run_gate secrets gate_secrets
run_gate docstrings gate_docstrings
run_gate datasets gate_datasets
run_gate metavalidate gate_metavalidate
run_gate determinism gate_determinism
run_gate mutation gate_mutation
run_gate load gate_load
run_gate docker gate_docker
run_gate freshclone gate_freshclone

echo
echo "================ summary ================"
echo "passed : ${PASSED[*]:-none}"
echo "skipped: ${SKIPPED[*]:-none}"
echo "failed : ${FAILED[*]:-none}"
if [[ ${#FAILED[@]} -gt 0 ]]; then exit 1; fi
exit 0
