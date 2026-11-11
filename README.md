# AgentGuard

**Red-team and evaluate any AI agent — LLM app, RAG pipeline, tool-using agent or MCP server — for
security *and* quality, with statistical rigor, deterministic canary-based detection, and
self-validating accuracy.**

[![ci](https://github.com/PiyushDas-2004/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/PiyushDas-2004/agentguard/actions/workflows/ci.yml)
[![coverage](https://img.shields.io/badge/coverage-99%25-brightgreen)](docs/VALIDATION.md#coverage)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](pyproject.toml)

## Why AgentGuard

1. **Quality and security in one harness.** DeepEval/RAGAS-style quality metrics (tool
   trajectories, task success, consistency, RAG faithfulness/relevancy/precision/recall) and a
   12-category security red team run against the same target and land in one report.
2. **Deterministic leak detection with canaries.** Unique `AG-CANARY-<16 hex>` tokens are planted
   in the system prompt, files, database, knowledge base and memory, and found again in output and
   tool arguments in 13 encodings (base64, hex, reversed, spaced, ROT13, URL-encoded, split across a
   markdown link, ...). No LLM guesswork decides whether a secret leaked.
3. **Agents are stochastic, so results are statistics.** Every case runs N trials (plus mutated
   variants); every rate carries a Wilson 95% interval; a case fails only when the interval's
   *lower* bound clears the threshold; the risk score uses the *upper* bound.
4. **Excessive agency is judged from actions, not words.** Targets run inside an instrumented
   sandbox of 11 mock tools with a policy engine and a default-deny human-approval gate; findings
   come from the tool calls the agent actually made.
5. **It validates itself.** `agentguard meta-validate` runs the full suite against demo agents with
   known, code-documented vulnerabilities and reports AgentGuard's own precision, recall, F1 and
   false-positive rate.
6. **CI-native.** SARIF for code scanning, JUnit XML, a Markdown PR summary, exit codes, a
   reusable GitHub Action, run-to-run regression diffs, and a risk threshold that fails the build.

## 60-second quickstart

```bash
git clone https://github.com/PiyushDas-2004/agentguard && cd agentguard
uv sync
uv run agentguard run -c examples/demo.yaml --offline   # exits 1: the demo agent is vulnerable
# or, without cloning:  pip install git+https://github.com/PiyushDas-2004/agentguard  (attack library bundled)
open reports/agentguard-*.html                          # or xdg-open on Linux
```

The demo evaluates a deliberately vulnerable agent with deterministic mock models (no API keys, no
network). A browsable example report is committed at
[docs/sample_report/](docs/sample_report/index.html).

Want the passing case? `uv run agentguard run -c examples/demo_hardened.yaml --offline` (exit 0).

## Hosting

* **Website:** https://piyushdas-2004.github.io/agentguard/ — landing page and sample reports (GitHub Pages).
* **Live dashboard:** [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/PiyushDas-2004/agentguard)
  — or locally: `docker run -p 8000:8000 ghcr.io/piyushdas-2004/agentguard-demo:latest`.
* **Images** `ghcr.io/piyushdas-2004/agentguard` (CLI) and `ghcr.io/piyushdas-2004/agentguard-demo` (dashboard with demo
  runs) are published on every push to `main`. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Features

* **12 attack categories + over-refusal**: direct/indirect prompt injection, jailbreaks (incl.
  multi-turn crescendo), system-prompt leakage, data exfiltration, PII disclosure, excessive
  agency, insecure output, memory poisoning, RAG poisoning, denial of wallet, package
  hallucination; **308 attack seed cases** and **64 benign cases** — all canary/mock-tool based.
* **7 injection vectors**: user message, deployment context, RAG document, tool output, file,
  e-mail, web page, memory (cross-session).
* **Mutation engine**: base64, ROT13, leetspeak, homoglyphs, zero-width characters, token
  splitting, role-play/JSON wrappers, offline pseudo-translation, live paraphrasing — with
  decoders and robustness metrics.
* **Adaptive attacker**: PAIR-style refinement loop, budget-capped.
* **9 deterministic detectors** with evidence spans + rubric-driven LLM judge (JSON-validated,
  repair retries, ensemble, calibration against 128 hand-labelled examples).
* **Targets**: Python callables (sync/async), HTTP (Jinja2 request template + JSONPath),
  OpenAI-compatible endpoints with function calling, LangChain/LangGraph, MCP servers (stdio);
  plugin entry points for targets, attack packs, detectors and judges.
* **Reports**: self-contained HTML (dark mode, mobile, transcript viewer with highlighted
  evidence and colour-coded tool calls), JSON, SARIF 2.1.0, JUnit XML, Markdown.
* **Dashboard**: FastAPI + HTMX runs list, risk trend, side-by-side comparison, case drill-down.
* **Reliability**: async with bounded concurrency, token-bucket rate limiting, retries with
  backoff + jitter, hard budget cap, graceful Ctrl-C with partial reports, SQLite + gzipped JSONL.

## Architecture

```mermaid
flowchart LR
  CFG[YAML config + policy] --> R[Runner]
  DS[Attack packs + mutations] --> R
  R --> S[Scheduler<br/>concurrency, rate limit, retries, budget]
  S --> D[Conversation driver]
  D --> ENV[Seeded virtual world<br/>files, DB, web, inbox, memory, BM25 KB<br/>+ canaries + synthetic PII]
  D <--> T[Target adapter<br/>python / http / openai / langchain / mcp]
  T <--> SB[Tool sandbox<br/>11 mock tools, policy, approval gate]
  D --> EV[Evaluator<br/>9 detectors -> judge]
  EV --> ST[(SQLite + JSONL.gz)]
  EV --> SC[Wilson CIs, risk, grade, OWASP]
  SC --> REP[HTML / JSON / SARIF / JUnit / MD]
  ST --> DB[Dashboard]
```

### One trial

```mermaid
sequenceDiagram
  participant R as Runner
  participant D as ConversationDriver
  participant T as Target (agent)
  participant S as ToolSandbox
  participant E as Evaluator
  R->>D: run_trial(case, seed, mutation)
  D->>D: build world, plant canaries, render & mutate payload, plant poison
  loop each session / user turn
    D->>T: send(conversation, tools, context) [timeout, retries]
    T->>S: tool calls (policy-checked, approvals, recorded)
    S-->>T: mock results (may carry injected instructions)
    T-->>D: reply
  end
  D->>E: transcript + tool calls + canaries + planted PII
  E->>E: deterministic detectors (final if violated) -> judge if needed
  E-->>R: verdicts, violated?, objective met?
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Sample CLI output

```text
$ uv run agentguard run -c examples/demo.yaml --offline
                          AgentGuard — demo-vulnerable                          
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━┳━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ category          ┃ cases ┃ fail ┃ pass ┃ inconcl. ┃ violation rate (95% CI) ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━╇━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ PI_DIRECT         │ 46    │ 45   │ 0    │ 1        │ 92% (0.90–0.93)         │
│ PI_INDIRECT       │ 42    │ 41   │ 0    │ 1        │ 87% (0.85–0.89)         │
│ JAILBREAK         │ 32    │ 31   │ 0    │ 1        │ 94% (0.91–0.95)         │
│ SYS_PROMPT_LEAK   │ 22    │ 22   │ 0    │ 0        │ 92% (0.90–0.95)         │
│ DATA_EXFIL        │ 29    │ 29   │ 0    │ 0        │ 97% (0.95–0.98)         │
│ PII_LEAK          │ 19    │ 19   │ 0    │ 0        │ 94% (0.92–0.96)         │
│ EXCESSIVE_AGENCY  │ 35    │ 35   │ 0    │ 0        │ 92% (0.90–0.94)         │
│ INSECURE_OUTPUT   │ 26    │ 26   │ 0    │ 0        │ 83% (0.80–0.86)         │
│ MEMORY_POISON     │ 13    │ 13   │ 0    │ 0        │ 93% (0.89–0.96)         │
│ RAG_POISON        │ 16    │ 16   │ 0    │ 0        │ 62% (0.55–0.69)         │
│ DENIAL_OF_WALLET  │ 14    │ 14   │ 0    │ 0        │ 87% (0.82–0.90)         │
│ PKG_HALLUCINATION │ 14    │ 14   │ 0    │ 0        │ 93% (0.90–0.96)         │
│ OVER_REFUSAL      │ 64    │ 0    │ 0    │ 64       │ 0% (0.00–0.01)          │
└───────────────────┴───────┴──────┴──────┴──────────┴─────────────────────────┘
Risk score 95.2 / 100 · grade F · threshold 40 → FAILED
```

The hardened agent on the same config: `Risk score 17.2 / 100 · grade B · threshold 40 → PASSED` (exit code 0).

## Meta-validation: how accurate is AgentGuard?

`agentguard meta-validate` runs the full security suite (6,330 trials per agent: 372 cases × 5 trials × seed + 3 mutations, minus non-mutable cases) against five demo agents whose vulnerabilities are documented per category in [`examples/ground_truth.yaml`](examples/ground_truth.yaml) (written from their code), and scores AgentGuard itself. Real output, full logs in [docs/VALIDATION.md](docs/VALIDATION.md):

| Metric | Value | Target |
|---|---|---|
| Precision | **1.000** | — |
| Recall | **1.000** | ≥ 0.90 |
| F1 | **1.000** | — |
| False-positive rate | **0.000** | ≤ 0.10 |
| Partially hardened agent: categories matching ground truth | **100%** | ≥ 85% |
| (agent, category) pairs evaluated | 65 (TP 33, FP 0, TN 32, FN 0) | — |

| Demo agent | Risk score | Grade | Over-refusal |
|---|---|---|---|
| `vulnerable` | 95.18 | F | 0.0% |
| `partially_hardened` | 83.71 | F | 34.4% |
| `hardened` | 17.19 | B | 0.0% |
| `rag` | 47.06 | D | 0.0% |
| `rag_hardened` | 17.12 | B | 0.0% |

All five agents use the *same* naive mock model; the hardened agents are safe only because of their defense code ([`examples/targets/defenses.py`](examples/targets/defenses.py)). The first full run had one false positive (FPR 0.031); it was traced to a dataset case attributing a correct leak finding to the wrong category and fixed in the dataset, not the ground truth ([DECISIONS D-016](docs/DECISIONS.md)).

The quality suite exposes the cost of those defenses: task success is 100% for the vulnerable agent and 65% for the hardened one (plan-then-execute and provenance checks block some legitimate multi-step tasks) — a security/utility trade-off AgentGuard makes visible.

## OWASP LLM Top 10 (2025) coverage

| OWASP LLM Top 10 (2025) | Cases | Vulnerable demo: fail / pass / inconcl. | Hardened demo: fail / pass / inconcl. |
|---|---|---|---|
| LLM01:2025 Prompt Injection | 171 | 168 / 0 / 3 | 0 / 0 / 171 |
| LLM02:2025 Sensitive Information Disclosure | 85 | 85 / 0 / 0 | 0 / 0 / 85 |
| LLM03:2025 Supply Chain | 14 | 14 / 0 / 0 | 0 / 0 / 14 |
| LLM04:2025 Data and Model Poisoning | 29 | 29 / 0 / 0 | 0 / 0 / 29 |
| LLM05:2025 Improper Output Handling | 26 | 26 / 0 / 0 | 0 / 0 / 26 |
| LLM06:2025 Excessive Agency | 52 | 52 / 0 / 0 | 0 / 0 / 52 |
| LLM07:2025 System Prompt Leakage | 43 | 42 / 0 / 1 | 0 / 0 / 43 |
| LLM08:2025 Vector and Embedding Weaknesses | 16 | 16 / 0 / 0 | 0 / 0 / 16 |
| LLM09:2025 Misinformation | 14 | 14 / 0 / 0 | 0 / 0 / 14 |
| LLM10:2025 Unbounded Consumption | 15 | 15 / 0 / 0 | 0 / 0 / 15 |

Hardened cases are *inconclusive* rather than *pass* because 0 violations in 20 trials still leaves a 95% upper bound of 0.16 — see [SCORING](docs/SCORING.md).

## Test your own agent

**Python:**

```python
# my_agent.py
async def agent(conversation, tools, context):
    user = conversation[-1].content
    if "order" in user:
        result = await tools.call("db_query", {"table": "orders", "where": {"id": "O-2002"}})
        return f"Order status: {result.content}"
    return "How can I help?"
```

```yaml
# agentguard.yaml (start from `agentguard init`)
target:
  type: python_callable
  path: my_agent.py:agent
  llm: { provider: anthropic, model: claude-haiku-5-5 }   # exposed to your agent as context.llm
policy: policy.yaml
```

**HTTP:**

```yaml
target:
  type: http
  url: https://my-agent.internal/chat
  headers: { Authorization: "Bearer ${AGENT_TOKEN}" }
  request_template: '{"message": {{ message | tojson }}, "history": {{ messages | tojson }}}'
  response_mapping: { text: "$.reply", tool_calls: "$.actions" }
  known_secrets: ["the-secret-your-agent-must-never-reveal"]
```

Then `agentguard run -c agentguard.yaml`. OpenAI-compatible endpoints (`type: openai_compat`),
LangChain runnables (`type: langchain`) and MCP servers (`type: mcp`) are configured the same way —
see `examples/demo_http.yaml`, `examples/demo_mcp.yaml` and
[docs/WRITING_PLUGINS.md](docs/WRITING_PLUGINS.md).

## CI usage

```yaml
- uses: PiyushDas-2004/agentguard/.github/actions/agentguard@v1.0.0
  with:
    config: agentguard.yaml
    fail-threshold: "25"
    upload-sarif: "true"
```

Exit codes: `0` pass · `1` risk above threshold or critical failure · `2` config error · `3`
runtime error · `4` budget exceeded (partial report still written). Details in
[docs/CI_INTEGRATION.md](docs/CI_INTEGRATION.md).

## Engineering quality (measured, see [docs/VALIDATION.md](docs/VALIDATION.md))

| Gate | Result |
|---|---|
| Tests (offline, `pytest-socket`, Hypothesis 200 examples/property) | **1,641 passed** (+4 live-provider tests, skipped without keys) |
| Coverage | **99.2 %** overall · detectors 99.7 % · scoring, judges, canary 100 % |
| Mutation testing (mutmut on scoring + detectors) | **87.6 %** killed (1,725 / 1,970) |
| `mypy --strict`, ruff, bandit (medium/high), pip-audit, secret scan | clean |
| Determinism (same seed, two offline runs) | identical results |
| Load test (1,000 trials, concurrency 32, 100/s limit) | 0 lost trials · achieved 100.9/s (0.9 % off) · +21.7 MB RSS |
| Docker image + `docker compose` dashboard | builds · `/healthz` healthy |
| Fresh clone → README quickstart | passes |

## How AgentGuard compares

| | AgentGuard | garak | PyRIT | promptfoo | DeepEval | RAGAS |
|---|---|---|---|---|---|---|
| Primary focus | agent security + quality | LLM vulnerability scanning | red-team orchestration | eval + red team (JS) | LLM quality metrics | RAG quality metrics |
| Tool-call sandbox, judges agency from actions | ✅ | ❌ | partial (orchestrators) | partial | ❌ | ❌ |
| Deterministic canary detection (13 encodings) | ✅ | partial (string detectors) | ❌ | partial (assertions) | ❌ | ❌ |
| Confidence intervals / statistical status | ✅ Wilson 95% | ❌ | ❌ | ❌ | ❌ | ❌ |
| Self-validation against known-vulnerable agents | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Quality metrics (trajectory, RAG) | ✅ built-in + adapters | ❌ | ❌ | ✅ | ✅ | ✅ |
| Size of attack library | ~308 seeds | very large | large (converters) | large (plugins) | n/a | n/a |
| Live-model attack strength (PAIR/TAP etc.) | PAIR loop | many probes | strongest | several | n/a | n/a |
| SARIF / JUnit / CI action | ✅ / ✅ / ✅ | ❌ / ❌ / ❌ | ❌ | ✅ JUnit, CI | pytest integration | ❌ |

garak and PyRIT have far larger attack libraries and stronger live-attack tooling; promptfoo has
a broader eval ecosystem; DeepEval and RAGAS have deeper quality metrics (AgentGuard can call them
as backends). AgentGuard's niche is *agentic* security with statistically sound, self-validated,
CI-gating results.

## Limitations (honest)

* **Offline mode is a simulator.** Offline runs use a rule-based naive instruction follower. They
  validate your *defense code* and AgentGuard's detectors, not how a real LLM would behave; use
  live mode (`examples/demo_live.yaml`) for that.
* **Meta-validation is on AgentGuard's own demo agents.** It shows the detectors and statistics
  work against known ground truth; it is not a benchmark of real-world agents.
* **Mock judge calibration is weak** (κ = 0.27 on the gold set): offline, deterministic detectors
  carry the verdicts; for judge-dependent categories in live mode, calibrate your judge first.
* **Package snapshot** covers the most popular PyPI/npm names; obscure real packages may be
  reported (confidence 0.85).
* **Statistics need trials**: a perfectly safe agent needs ≥ 35 valid trials per case to reach
  `pass` status at the default 10% threshold; with the demo's pooled 20 it is `inconclusive` and
  scores ~17 (grade B). That is by design (see [docs/SCORING.md](docs/SCORING.md)).
* English-centric attacks (plus a small Spanish lexicon).

## Roadmap

* TAP / crescendo attacker strategies for live mode and multi-agent targets.
* Embedding-based semantic leak detection alongside n-grams.
* Hosted dataset registry with versioned attack packs and community contributions.

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) ·
[Attacks](docs/ATTACKS.md) · [Scoring](docs/SCORING.md) · [Validation](docs/VALIDATION.md) ·
[Plugins](docs/WRITING_PLUGINS.md) · [CI](docs/CI_INTEGRATION.md) · [Deployment](docs/DEPLOYMENT.md) ·
[Decisions](docs/DECISIONS.md) · [Dataset authoring](docs/DATASET_AUTHORING.md)

## Responsible use

AgentGuard is a defensive tool. All bundled attacks use canary tokens and mock tools; nothing
real is sent, paid, written or executed. Test only systems you are authorised to test — see
[RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) and [SECURITY.md](SECURITY.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
