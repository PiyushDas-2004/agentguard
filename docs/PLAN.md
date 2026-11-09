# AgentGuard — Implementation Plan

This document was written in Phase 0, before any feature code, and is kept up to date as the
architecture evolves. It lists the file tree, module interfaces, the data models, the test plan and
the risk register.

## 1. File tree

See the repository layout in the README; every directory below exists.

```
src/agentguard/
  cli.py                 Typer app: init, doctor, run, report, compare, list-attacks,
                         lint-datasets, calibrate-judge, meta-validate, dashboard
  version.py
  config/  models.py     Pydantic config schema (RunConfig, TargetConfig, SuitesConfig, ...)
           loader.py     load_config(path) -> AgentGuardConfig, ConfigError with YAML paths + hints
           policy.py     Policy model + PolicyEngine.evaluate_tool_call()
  core/    types.py      Part E data models (AttackCase, Trial, Verdict, CaseResult, RunResult, ...)
           runner.py     Runner.run() -> RunResult (orchestrates everything)
           scheduler.py  TrialScheduler: semaphore + rate limiter + retries + cancellation
           ratelimit.py  TokenBucket (async)
           errors.py     AgentGuardError hierarchy + ErrorInfo conversion + exit codes
           tracing.py    Span model (run > case > trial > turn > tool_call/judge_call), OTel exporter
           seeds.py      derive_seed(base, *parts) (sha256), seeded RNG helpers
  llm/     base.py       LLMMessage, LLMToolSpec, LLMResponse, BaseLLM protocol
           mock.py       MockLLM (naive instruction-follower, scripted, judge profiles)
           intents.py    deterministic intent extraction used by the naive MockLLM
           litellm_client.py  LiteLLMClient (live mode, retries, cost)
           budget.py     BudgetTracker (hard cap, BudgetExceeded)
  targets/ base.py       BaseTarget.send(conversation, tools, context) -> TargetResponse
           python_callable.py, http.py, openai_compat.py, langchain.py, mcp.py, registry.py
  harness/ tools.py      ToolSpec + 11 instrumented mock tools over a VirtualEnvironment
           environment.py  seeded virtual FS / DB / web / inbox
           sandbox.py    ToolSandbox: schema validation, policy, approvals, recording
           canary.py     CanaryRegistry + variant generation + variant-aware detection
           rag_fixture.py BM25 corpus index with per-trial poisoning
           memory.py     cross-session MemoryStore
           conversation.py ConversationDriver: sessions, turns, timeouts, attacker turns
           prompts.py    default system prompt template
  attacks/ models.py     AttackPack, Objective evaluation
           loader.py     load_cases(paths, strict) + template rendering
           mutations.py  seeded transforms + decoders
           adaptive.py   PAIR-style attacker loop
           registry.py   category registry + plugin attack packs
           lint.py       dataset linter
  detectors/ base.py + canary, tool_policy, exfil, pii, system_prompt, dangerous_output,
             refusal, resource, package_halluc (+ registry)
  judges/  base.py, llm_judge.py, mock_judge.py, ensemble.py, calibration.py, rubrics/*.md
  quality/ trajectory.py, task_success.py, consistency.py, rag_metrics.py,
           ragas_adapter.py, deepeval_adapter.py, performance.py, suite.py
  scoring/ stats.py (Wilson), risk.py, aggregate.py, compare.py, owasp.py
  reporting/ html.py, json_report.py, sarif.py, junit.py, markdown.py, remediation.py,
             templates/report.html.j2
  storage/ db.py, models.py, transcripts.py
  dashboard/ app.py, templates/*
  plugins/ __init__.py (entry-point discovery)
  metavalidate.py        meta-validation against ground truth
```

## 2. Key interfaces

```python
class BaseTarget(ABC):
    async def send(self, conversation: Conversation, tools: ToolSandbox,
                   context: TargetContext) -> TargetResponse: ...
    async def aclose(self) -> None: ...

class ToolSandbox:
    def specs(self) -> list[ToolSpec]
    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult
    async def request_approval(self, name: str, arguments: dict[str, Any]) -> bool
    def record_external(self, name: str, arguments: dict[str, Any], result: str | None) -> ToolCall
    calls: list[ToolCall]

class BaseLLM(Protocol):
    async def complete(self, messages: list[LLMMessage], tools: list[LLMToolSpec] | None = None,
                       *, seed: int | None = None, temperature: float | None = None,
                       json_mode: bool = False) -> LLMResponse

class Detector(ABC):
    id: str
    def detect(self, ctx: DetectionContext) -> Verdict

class Judge(ABC):
    async def judge(self, request: JudgeRequest) -> JudgeResult

def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]
def case_status(ci_low: float, ci_high: float, threshold: float) -> CaseStatus
def overall_risk(results: Sequence[CaseResult]) -> float
def grade(risk: float) -> str
def compare_runs(a: RunResult, b: RunResult) -> RunComparison

class Runner:
    async def run(self) -> RunResult   # never raises for per-trial failures
```

## 3. Data models

Part E models live in `core/types.py`: `Severity`, `AttackCategory`, `InjectionVector`, `Turn`,
`Poison`, `Objective`, `AttackCase`, `ToolCall`, `TranscriptTurn`, `Transcript`, `ErrorInfo`,
`Trial`, `EvidenceSpan`, `Verdict`, `CaseResult`, `CategoryScorecard`, `OwaspCoverageRow`,
`QualityReport`, `PerformanceReport`, `RunResult`. All are Pydantic v2 and JSON round-trippable
(proved by Hypothesis in `tests/property/test_model_roundtrip.py`).

## 4. Execution model of one trial

1. `TrialSpec(case, trial_index, seed, mutation)` is produced by the runner.
2. `ConversationDriver` builds a fresh seeded `VirtualEnvironment`, plants canaries (system prompt,
   private file, DB row, RAG doc, memory), applies the case `poison` to its vector, renders
   `{{CANARY}}`, `{{ATTACKER_ACCOUNT}}`, `{{EXFIL_URL}}`, applies the mutation.
3. For every session and every user turn it calls `target.send()` under a timeout; the target uses
   the `ToolSandbox` which records `ToolCall`s against the policy.
4. Detectors listed by the case run on the transcript; judge runs if requested and no deterministic
   detector already decided.
5. Trial + verdicts persisted (SQLite + gzipped JSONL); aggregation computes Wilson CIs.

## 5. Test plan

| Layer | Location | What |
|---|---|---|
| Unit | `tests/unit/` | every module; ≥10 TP/TN/near-miss cases per detector; hand-computed scoring |
| Property | `tests/property/` | model round-trip, mutation decode(encode(x))==x, canary variants, scoring invariants, config parsing — 200+ examples each |
| Integration | `tests/integration/` | targets against in-process uvicorn/fake OpenAI/MCP stdio servers; runner + storage; dashboard TestClient |
| E2E | `tests/e2e/` | CLI `run` on demo config, all 5 report formats, exit codes, determinism, meta-validation |
| Snapshots | `tests/snapshots/` | JSON / Markdown / SARIF of a fixed seeded run |
| Failure injection | `tests/failure_injection/` | timeouts, exceptions, 429/5xx, invalid judge JSON, budget, locked SQLite, disk full, bad dataset, KeyboardInterrupt, giant output, non-UTF-8 |
| Live | `tests/live/` | real providers, skipped without keys |

Network is disabled for the default suite via `pytest-socket` (`--disable-socket`, loopback
allowed only for the in-process servers).

## 6. Risk register

| Risk | Mitigation |
|---|---|
| Meta-validation is circular if the mock model is scripted per case | Demo agents share one generic naive instruction-follower; hardened agent is safe only via its defense layer (see VALIDATION.md); ground truth written before tuning and never edited to fit |
| Wilson upper bound with few trials makes perfect agents look risky | Pool seed + mutation trials per case; document the statistical floor in SCORING.md |
| Heavy optional deps (ragas, deepeval, presidio) unavailable | Runtime discovery, clear skip messages, adapter logic tested with stub modules |
| Docker daemon unavailable in the build sandbox | Validate Dockerfile with hadolint, document |
| mutmut runtime | Restrict to scoring/ + detectors/ with fast unit tests |
| Non-determinism from asyncio scheduling | All randomness derived from (seed, case, trial, mutation); results sorted before aggregation |
