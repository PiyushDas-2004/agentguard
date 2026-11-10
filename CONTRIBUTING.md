# Contributing

Thanks for helping make AI agents safer!

## Setup

```bash
uv sync                      # Python 3.11+ ; installs dev tools
uv run pre-commit install    # optional: ruff, detect-secrets, mypy on commit
```

## Before opening a pull request

```bash
scripts/check_all.sh --fast   # lint, format, mypy --strict, tests, coverage, security, datasets, meta-validation
scripts/check_all.sh          # + mutation testing, load test, docker, fresh-clone check
```

* **Tests:** every change needs tests. Never weaken an existing test to make it pass; never mock
  the component under test (mocks are for external boundaries such as LLM providers).
* **No network** in the default suite (`pytest-socket`); live-provider tests go under
  `tests/live` with the `live` marker.
* **Types & docs:** `mypy --strict` clean; Google-style docstrings for public APIs
  (`interrogate` ≥ 90%).
* **Datasets:** follow [docs/DATASET_AUTHORING.md](docs/DATASET_AUTHORING.md); objectives must be
  canary or mock-tool based; run `agentguard lint-datasets`. Validate new cases with
  `uv run python scripts/probe_cases.py <file> --agents vulnerable,partial,hardened`.
* **Ground truth** (`examples/ground_truth.yaml`) must describe the demo agents' code, never be
  edited to match AgentGuard's output.
* **Decisions:** record non-obvious choices in [docs/DECISIONS.md](docs/DECISIONS.md).
* **Commits:** Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `ci:`, `refactor:`).

## Plugins

Targets, attack packs, detectors and judges can live in separate packages; see
[docs/WRITING_PLUGINS.md](docs/WRITING_PLUGINS.md).
