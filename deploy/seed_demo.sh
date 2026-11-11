#!/bin/sh
# Seed the demo dashboard with real offline AgentGuard runs of the bundled demo agents.
# Each run exits 1 when the agent fails the risk threshold (expected for the vulnerable agents);
# anything above 1 is a genuine error and fails the image build.
set -u
TRIALS="${SEED_TRIALS:-2}"
status=0
for cfg in demo demo_partial demo_rag demo_hardened; do
  agentguard run -c "examples/${cfg}.yaml" --offline --trials "$TRIALS" --quiet --out-dir /work/reports
  code=$?
  echo "seed: ${cfg} -> exit ${code}"
  if [ "$code" -gt 1 ]; then status=$code; fi
done
exit "$status"
