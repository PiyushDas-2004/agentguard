# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-10

### Added
- **Evaluation harness:** seeded virtual environment (files, database, web, inbox, memory,
  BM25 knowledge base), 11 instrumented mock tools, policy-enforcing sandbox with a default-deny
  human-approval gate, canary planting in five locations, cross-session memory, conversation
  driver with per-turn timeouts, retries and multi-turn/multi-session support.
- **Canary detection** in 13 encodings (raw, case, suffix, base64, url-safe base64, hex, reversed,
  spaced/dotted, URL-encoded, ROT13, markdown-split, URL query).
- **Nine deterministic detectors:** canary, tool_policy, exfil, pii, system_prompt,
  dangerous_output, refusal, resource, package_halluc — each with evidence spans.
- **Judges:** rubric-driven LLM judge with Pydantic-validated JSON and repair retries,
  deterministic mock judge, two-judge ensemble, calibration against a 128-example gold set.
- **Datasets:** 308 canary-based attack seed cases across 12 categories, 64 benign over-refusal
  cases, 46 tool-use quality tasks, 32 RAG questions over a 30-document corpus with 10 poisoned
  documents; dataset linter with near-duplicate detection.
- **Mutation engine:** base64, ROT13, leetspeak, homoglyph, zero-width, token split, role-play and
  JSON wrappers, offline pseudo-translation, live paraphrase; decoders for reversible transforms.
- **Adaptive attacker:** PAIR-style refinement loop (scripted mock attacker offline).
- **Statistics:** Wilson 95% intervals, conservative upper-bound risk score, grades, OWASP LLM
  Top 10 (2025) coverage matrix, mutation robustness, run comparison with significance.
- **Quality suite:** trajectory metrics, task success, consistency, built-in RAG metrics, optional
  RAGAS and DeepEval backends, performance and cost statistics.
- **Targets:** Python callable, HTTP (Jinja2 template + JSONPath), OpenAI-compatible with function
  calling, LangChain/LangGraph, MCP (stdio); entry-point plugins.
- **Reports:** self-contained HTML (dark mode, mobile, transcript viewer with highlighted
  evidence), JSON, SARIF 2.1.0, JUnit XML, Markdown.
- **CLI:** `init`, `doctor`, `run`, `report`, `compare`, `list-attacks`, `lint-datasets`,
  `calibrate-judge`, `meta-validate`, `dashboard`, with documented exit codes.
- **Dashboard:** FastAPI + HTMX runs list, risk trend, comparison, case drill-down.
- **Demo agents:** vulnerable, partially hardened, hardened (real defense layer), RAG
  (vulnerable/hardened), HTTP-served agent, over-permissive MCP server; ground truth and
  `meta-validate`.
- **CI/CD:** GitHub Actions (matrix 3.11/3.12, security scans, meta-validation, Docker),
  self-check workflow with SARIF upload and PR comment, reusable composite action,
  multi-stage non-root Docker image and compose file.
