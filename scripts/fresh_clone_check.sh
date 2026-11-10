#!/usr/bin/env bash
# Fresh-clone gate: clone the repository into a temporary directory and run the README quickstart.
#
#   uv sync
#   uv run agentguard run -c examples/demo.yaml --offline
#
# The demo agent is deliberately vulnerable, so the run must exit 1 (risk above threshold) and
# write all five reports (html, json, sarif, junit, markdown).
#
# Usage:
#   scripts/fresh_clone_check.sh              # clone the committed HEAD
#   scripts/fresh_clone_check.sh --worktree   # snapshot tracked + untracked (non-ignored) files,
#                                             # i.e. what the next commit would contain
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$(pwd)"
export UV_SYSTEM_CERTS=1
unset UV_NATIVE_TLS || true
unset VIRTUAL_ENV || true

MODE="head"
for arg in "$@"; do
  case "$arg" in
    --worktree) MODE="worktree" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

WORK="$(mktemp -d -t agentguard-fresh-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
DEST="$WORK/agentguard"

if [[ "$MODE" == "head" ]]; then
  echo "fresh_clone: git clone $REPO (HEAD $(git rev-parse --short HEAD)) -> $DEST"
  git clone --quiet --no-hardlinks "$REPO" "$DEST"
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "fresh_clone: note — the working tree has uncommitted changes; they are NOT part of this check (use --worktree)"
  fi
else
  echo "fresh_clone: snapshot of tracked + untracked (non-ignored) files -> $DEST"
  mkdir -p "$DEST"
  git ls-files -z --cached --others --exclude-standard \
    | (cd "$REPO" && xargs -0 -I{} sh -c 'test -e "{}" && printf "%s\0" "{}"' ) \
    | tar --null -T - -cf - | tar -xf - -C "$DEST"
  git -C "$DEST" init --quiet
fi

cd "$DEST"
test ! -e .venv || { echo "fresh_clone: FAIL — clone unexpectedly contains .venv" >&2; exit 1; }

echo "fresh_clone: uv sync"
uv sync --quiet
uv run agentguard --version

echo "fresh_clone: uv run agentguard run -c examples/demo.yaml --offline"
set +e
uv run agentguard run -c examples/demo.yaml --offline --quiet > "$WORK/run.log" 2>&1
code=$?
set -e
tail -n 12 "$WORK/run.log"
if [[ $code -ne 1 ]]; then
  echo "fresh_clone: FAIL — expected exit code 1 (vulnerable demo above threshold), got $code" >&2
  cat "$WORK/run.log" >&2
  exit 1
fi

missing=0
for ext in html json sarif junit.xml md; do
  count=$(find reports -maxdepth 1 -name "agentguard-*.${ext}" -size +0 | wc -l)
  if [[ $count -ne 1 ]]; then
    echo "fresh_clone: FAIL — expected one non-empty reports/agentguard-*.${ext}, found $count" >&2
    missing=1
  else
    echo "fresh_clone: report ok  $(find reports -maxdepth 1 -name "agentguard-*.${ext}")"
  fi
done
[[ $missing -eq 0 ]] || exit 1
uv run python -c "import json,glob; d=json.load(open(glob.glob('reports/*.json')[0])); assert d['total_trials'] > 0 and d['cases']; print(f\"fresh_clone: json ok ({d['total_trials']} trials, {len(d['cases'])} cases, risk {d['risk_score']:.1f}, grade {d['grade']})\")"
echo "fresh_clone: PASS (mode: $MODE)"
