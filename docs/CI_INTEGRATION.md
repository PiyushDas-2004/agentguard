# CI integration

AgentGuard is designed to gate merges: it emits SARIF for code scanning, JUnit XML for test
dashboards, a Markdown summary for PR comments, and exit codes for pass/fail.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | risk score ≤ threshold and no critical case failed |
| 1 | risk score above threshold, or a critical-severity case failed |
| 2 | configuration or usage error (message names the YAML path) |
| 3 | runtime error (or the run was interrupted) |
| 4 | budget exceeded — partial results are still saved and reported |

## Reusable GitHub Action

```yaml
# .github/workflows/agentguard.yml
name: agentguard
on: [pull_request]
permissions:
  contents: read
  security-events: write   # for SARIF upload
jobs:
  redteam:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: PiyushDas-2004/agentguard/.github/actions/agentguard@v1.0.0
        with:
          config: agentguard.yaml       # your config
          fail-threshold: "25"          # optional override of run.fail_threshold_risk
          upload-sarif: "true"
          offline: "false"              # true = deterministic mocks, no API calls
          version: "agentguard[litellm]"
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Inputs: `config` (required), `fail-threshold`, `upload-sarif`, `offline`, `version`.
Outputs: `risk-score`, `grade`. The action uploads the reports as an artifact, appends the
Markdown summary to the job summary, and fails the job with AgentGuard's exit code.

## Plain CLI (any CI)

```bash
pip install agentguard
agentguard run -c agentguard.yaml --fail-threshold 25 --out-dir reports/
# reports/agentguard-<run>.sarif      -> code scanning
# reports/agentguard-<run>.junit.xml  -> test reporting
# reports/agentguard-<run>.md         -> PR comment
```

GitLab example:

```yaml
agentguard:
  image: python:3.12-slim
  script:
    - pip install agentguard
    - agentguard run -c agentguard.yaml --out-dir reports/
  artifacts:
    when: always
    reports:
      junit: reports/*.junit.xml
    paths: [reports/]
```

## Regression gating between runs

Store the JSON report of `main` as a baseline and compare:

```bash
agentguard compare <baseline-run-id> <candidate-run-id>
```

Changes are flagged *significant* only when Wilson intervals do not overlap, which avoids
flapping on noisy agents.

## This repository's own self-check

`.github/workflows/self-check.yml` runs the demo config against the hardened agent (must pass)
and the vulnerable agent (must fail with exit code 1 — asserted), uploads SARIF to code scanning,
attaches the HTML reports and comments the Markdown summary on the PR.
