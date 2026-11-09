"""Run orchestration: config -> trials -> verdicts -> storage -> ``RunResult``."""

from __future__ import annotations

import asyncio
import logging
import secrets
import subprocess  # nosec B404 - used only to read the git SHA with a fixed argument list
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentguard.attacks.loader import load_cases, select_cases
from agentguard.attacks.mutations import plan_mutations
from agentguard.config.loader import config_hash, resolve_path
from agentguard.config.models import AgentGuardConfig, JudgeConfig, LLMConfig
from agentguard.config.policy import Policy, load_policy
from agentguard.core.errors import BudgetExceededError, ConfigError
from agentguard.core.ratelimit import TokenBucket
from agentguard.core.scheduler import TrialScheduler
from agentguard.core.seeds import derive_seed
from agentguard.core.tracing import Tracer
from agentguard.core.types import (
    AttackCase,
    AttackCategory,
    PerformanceReport,
    RunResult,
    TargetInfo,
    utcnow,
)
from agentguard.detectors.evaluate import TrialEvaluator
from agentguard.detectors.registry import DetectorRegistry
from agentguard.harness.conversation import ConversationDriver
from agentguard.harness.rag_fixture import RagCorpus
from agentguard.judges.base import Judge, JudgeResult
from agentguard.judges.ensemble import EnsembleJudge
from agentguard.judges.llm_judge import LLMJudge
from agentguard.judges.mock_judge import MockJudge
from agentguard.llm.budget import BudgetTracker
from agentguard.llm.factory import build_llm
from agentguard.scoring.aggregate import TrialRecord, aggregate_case, category_scorecards
from agentguard.scoring.owasp import coverage_matrix
from agentguard.scoring.risk import grade, over_refusal_rate, overall_risk
from agentguard.scoring.stats import percentile
from agentguard.storage.db import Database
from agentguard.storage.models import JudgeCallRow, RunRow
from agentguard.storage.transcripts import TranscriptStore
from agentguard.targets.base import BaseTarget, MeteredLLM
from agentguard.targets.registry import build_target
from agentguard.version import __version__

__all__ = ["RunOptions", "Runner", "TrialSpec", "build_judge", "git_sha", "new_run_id"]

logger = logging.getLogger(__name__)


def new_run_id() -> str:
    """Timestamped unique run id, e.g. ``20261109-153012-a1b2c3``."""
    return utcnow().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)


def git_sha() -> str | None:
    """Current git commit SHA (``None`` outside a repository)."""
    try:
        out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = out.stdout.strip()
    return sha or None


def build_judge(config: JudgeConfig, *, offline: bool, budget: BudgetTracker | None = None) -> Judge:
    """Create the configured judge (MockJudge offline), optionally as a two-judge ensemble."""

    def single(provider: str, model: str | None) -> Judge:
        if offline or provider == "mock":
            return MockJudge()
        llm = build_llm(LLMConfig(provider=provider, model=model))
        return LLMJudge(MeteredLLM(llm, budget, component="judge"), max_repair_retries=config.max_repair_retries)

    first = single(config.provider, config.model)
    if not config.ensemble:
        return first
    second = single(config.second_provider or config.provider, config.second_model or config.model)
    return EnsembleJudge(first, second)


@dataclass(frozen=True)
class TrialSpec:
    """One unit of scheduled work."""

    case: AttackCase
    trial_index: int
    seed: int
    mutation_id: str | None = None
    transform: str | None = None
    adaptive: bool = False


@dataclass
class RunOptions:
    """CLI overrides applied on top of the config file."""

    suite: str = "all"
    categories: list[AttackCategory] | None = None
    case_ids: list[str] | None = None
    trials: int | None = None
    offline: bool = False
    max_cost_usd: float | None = None
    fail_threshold: float | None = None
    strict: bool | None = None
    progress: Callable[[int, int], None] | None = None
    extra_target_options: dict[str, Any] = field(default_factory=dict)


class Runner:
    """Executes an AgentGuard run.

    Args:
        config: validated configuration.
        options: CLI overrides.
        base_dir: directory relative paths are resolved against (the config file's directory).
        target: pre-built target (tests/meta-validation); otherwise built from ``config.target``.
    """

    def __init__(
        self,
        config: AgentGuardConfig,
        options: RunOptions | None = None,
        *,
        base_dir: Path | None = None,
        target: BaseTarget | None = None,
        database: Database | None = None,
    ) -> None:
        self.config = config
        self.options = options or RunOptions()
        self.base_dir = base_dir or Path.cwd()
        self._target = target
        self.run_id = new_run_id()
        self.tracer = Tracer(otel=config.run.otel)
        max_cost = self.options.max_cost_usd if self.options.max_cost_usd is not None else config.run.max_cost_usd
        self.budget = BudgetTracker(max_cost_usd=max_cost)
        self.warnings: list[str] = []
        self._database = database
        self.records: dict[str, list[TrialRecord]] = defaultdict(list)
        self.result: RunResult | None = None

    # ------------------------------------------------------------------ setup helpers
    def _path(self, value: str) -> Path:
        return resolve_path(value, self.base_dir)

    @property
    def offline(self) -> bool:
        """Whether every model call is forced onto the deterministic mocks."""
        return self.options.offline

    def load_policy(self) -> Policy:
        """Resolve and load the policy file."""
        source = self.config.policy
        if isinstance(source, str):
            return load_policy(self._path(source), base_dir=self.base_dir)
        return load_policy(source)

    def load_cases(self) -> list[AttackCase]:
        """Load and filter the security (and benign) cases for this run."""
        security = self.config.suites.security
        if self.options.suite == "quality" or not security.enabled:
            return []
        strict = self.options.strict if self.options.strict is not None else self.config.run.strict_datasets
        result = load_cases([self._path(p) for p in security.datasets], strict=strict)
        self.warnings.extend(result.warnings)
        categories = self.options.categories
        if categories is None and security.categories != "all":
            categories = list(security.categories)
        case_ids = self.options.case_ids or security.cases or None
        cases = select_cases(result.cases, categories=categories, case_ids=case_ids)
        if not cases:
            raise ConfigError("no attack cases selected — check suites.security.datasets / --category / --case")
        return sorted(cases, key=lambda c: c.id)

    def plan(self, cases: list[AttackCase]) -> list[TrialSpec]:
        """Expand cases into seed and mutated trial specs."""
        trials = self.options.trials or self.config.run.trials_per_case
        seed = self.config.run.seed
        mutations = self.config.suites.security.mutations
        adaptive = self.config.suites.security.adaptive
        specs: list[TrialSpec] = []
        for case in cases:
            use_adaptive = adaptive.enabled and case.adaptive
            for index in range(trials):
                specs.append(
                    TrialSpec(
                        case,
                        index,
                        derive_seed(seed, case.id, "seed", index),
                        adaptive=use_adaptive,
                    )
                )
            if not mutations.enabled or use_adaptive:
                continue
            if case.poison is not None and not case.poison.content:
                continue
            for mutation in plan_mutations(case, mutations.transforms, mutations.per_case, seed, live=not self.offline):
                for index in range(trials):
                    specs.append(
                        TrialSpec(
                            case,
                            index,
                            derive_seed(seed, case.id, mutation.mutation_id, index),
                            mutation_id=mutation.mutation_id,
                            transform=mutation.transform,
                        )
                    )
        return specs

    def _llm_factory(self) -> Callable[[int], Any] | None:
        llm_config = self.config.target.llm
        if self.config.target.type not in {"python_callable", "langchain", "mcp"}:
            return None
        if self.offline and llm_config.provider != "mock":
            self.warnings.append("offline mode: target LLM replaced by MockLLM(profile=vulnerable)")

        def factory(seed: int) -> Any:
            return build_llm(llm_config, seed, offline=self.offline)

        return factory

    def _rag_corpus(self) -> RagCorpus | None:
        path = self._path("datasets/rag_corpus")
        return RagCorpus.load(path) if path.exists() else None

    @property
    def database(self) -> Database:
        """The results database (created on first use)."""
        if self._database is None:
            self._database = Database(self._path(self.config.storage.db_path))
        return self._database

    # ------------------------------------------------------------------ execution
    async def run(self) -> RunResult:
        """Execute the run; partial results are returned on budget exhaustion or interruption."""
        started_at = utcnow()
        t0 = time.perf_counter()
        policy = self.load_policy()
        cases = self.load_cases()
        specs = self.plan(cases)
        target = self._target or build_target(self.config.target)
        target_config = self.config.target
        judge = build_judge(self.config.judge, offline=self.offline, budget=self.budget)
        evaluator = TrialEvaluator(DetectorRegistry(), judge)
        driver = ConversationDriver(
            target,
            policy,
            llm_factory=self._llm_factory(),
            rag_corpus=self._rag_corpus(),
            budget=self.budget,
            timeout_seconds=self.config.run.timeout_seconds,
            max_retries=self.config.run.max_retries,
            retry_base_seconds=self.config.run.retry_base_seconds,
            max_output_chars=self.config.run.max_output_chars,
            system_prompt=target_config.system_prompt,
            known_secrets=target_config.known_secrets,
            target_options={**target_config.options, **self.options.extra_target_options},
        )
        store = TranscriptStore(self._path(self.config.storage.transcripts_dir))
        db = self.database
        db.start_run(
            RunRow(
                id=self.run_id,
                name=self.config.run.name,
                started_at=started_at,
                target_type=target_config.type,
                target_name=target.name,
                config_hash=config_hash(self.config),
            )
        )
        limiter = TokenBucket(self.config.run.rate_limit_per_second) if self.config.run.rate_limit_per_second else None
        scheduler: TrialScheduler = TrialScheduler(self.config.run.concurrency, limiter)
        total = len(specs)
        done = 0
        pending_writes: list[TrialRecord] = []

        def flush() -> None:
            if not pending_writes:
                return
            batch = list(pending_writes)
            pending_writes.clear()
            db.save_trials([(r.trial, r.verdicts) for r in batch])
            store.append([r.trial for r in batch])

        async def record_judge(trial_id: str, result: JudgeResult) -> None:
            db.save_judge_call(
                JudgeCallRow(
                    run_id=self.run_id,
                    trial_id=trial_id,
                    judge_id=result.judge_id,
                    rubric=result.rubric,
                    raw_output=result.raw[:20000],
                    violated=result.violated,
                    attempts=result.attempts,
                )
            )

        async def work(spec: TrialSpec) -> TrialRecord:
            with self.tracer.span("trial", spec.case.id, mutation=spec.mutation_id or "seed", index=spec.trial_index):
                if spec.adaptive:
                    from agentguard.attacks.adaptive import run_adaptive_trial

                    trial_run = await run_adaptive_trial(
                        driver,
                        spec.case,
                        run_id=self.run_id,
                        trial_index=spec.trial_index,
                        seed=spec.seed,
                        config=self.config.suites.security.adaptive,
                        budget=self.budget,
                        offline=self.offline,
                    )
                else:
                    trial_run = await driver.run_trial(
                        spec.case,
                        run_id=self.run_id,
                        trial_index=spec.trial_index,
                        seed=spec.seed,
                        mutation_id=spec.mutation_id,
                        transform=spec.transform,
                    )
                verdicts = await evaluator.evaluate(trial_run, policy, on_judge=record_judge)
                return TrialRecord(trial_run.trial, verdicts)

        def on_result(record: TrialRecord) -> None:
            nonlocal done
            done += 1
            self.records[record.trial.case_id].append(record)
            pending_writes.append(record)
            if len(pending_writes) >= 50:
                flush()
            if self.options.progress is not None:
                self.options.progress(done, total)

        await target.start()
        try:
            with self.tracer.span("run", self.run_id):
                outcome = await scheduler.run(specs, work, on_result)
        finally:
            flush()
            await target.aclose()

        abort_reason = outcome.aborted
        quality = None
        if abort_reason is None and self.options.suite in {"quality", "all"} and self.config.suites.quality is not None:
            from agentguard.quality.suite import run_quality_suite

            try:
                quality = await run_quality_suite(self, driver, policy, judge)
            except BudgetExceededError:
                abort_reason = "budget"
        if abort_reason == "budget":
            self.warnings.append(str(outcome.error) if outcome.error else "budget exceeded")
        result = self._finish(cases, target, started_at, t0, abort_reason, quality)
        db.finish_run(result)
        self.result = result
        return result

    def _finish(
        self,
        cases: list[AttackCase],
        target: BaseTarget,
        started_at: Any,
        t0: float,
        abort_reason: str | None,
        quality: Any,
    ) -> RunResult:
        run_cfg = self.config.run
        threshold = run_cfg.status_threshold
        embed = self.config.reports.embed_trials_per_case
        case_results = [
            aggregate_case(
                case,
                self.records[case.id],
                threshold=threshold,
                max_error_fraction=run_cfg.max_error_fraction,
                embed_samples=embed,
            )
            for case in cases
            if self.records.get(case.id)
        ]
        risk = overall_risk(case_results)
        all_records = [r for rs in self.records.values() for r in rs]
        latencies = [t.latency_ms for r in all_records for t in r.trial.transcript.turns if t.role.value == "assistant"]
        tokens_in = sum(r.trial.transcript.tokens_in for r in all_records)
        tokens_out = sum(r.trial.transcript.tokens_out for r in all_records)
        errors = sum(1 for r in all_records if r.trial.error is not None)
        performance = PerformanceReport(
            n_calls=len(latencies),
            latency_p50_ms=round(percentile(latencies, 50), 3),
            latency_p95_ms=round(percentile(latencies, 95), 3),
            latency_p99_ms=round(percentile(latencies, 99), 3),
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=round(sum(r.trial.transcript.cost_usd for r in all_records), 8),
            cost_per_task_usd=round(sum(r.trial.transcript.cost_usd for r in all_records) / len(all_records), 10)
            if all_records
            else 0.0,
            error_rate=errors / len(all_records) if all_records else 0.0,
        )
        threshold_risk = (
            self.options.fail_threshold if self.options.fail_threshold is not None else run_cfg.fail_threshold_risk
        )
        ended = utcnow()
        target_cfg = self.config.target
        return RunResult(
            run_id=self.run_id,
            name=run_cfg.name,
            started_at=started_at,
            ended_at=ended,
            duration_s=round(time.perf_counter() - t0, 3),
            partial=abort_reason is not None,
            abort_reason=abort_reason,
            target=TargetInfo(
                type=target_cfg.type,
                name=target.name,
                details={**target.describe(), "llm": target_cfg.llm.model_dump(mode="json")},
            ),
            config_hash=config_hash(self.config),
            git_sha=git_sha(),
            agentguard_version=__version__,
            seed=run_cfg.seed,
            trials_per_case=self.options.trials or run_cfg.trials_per_case,
            fail_threshold_risk=threshold_risk,
            status_threshold=threshold,
            cases=case_results,
            categories=category_scorecards(case_results),
            quality=quality,
            risk_score=risk,
            grade=grade(risk),
            over_refusal_rate=over_refusal_rate(case_results),
            owasp_coverage=coverage_matrix(case_results),
            total_cost_usd=round(self.budget.spent_usd, 8),
            total_trials=len(all_records),
            total_errors=errors,
            performance=performance,
            warnings=list(dict.fromkeys(self.warnings)),
        )


def run_sync(runner: Runner) -> RunResult:
    """Run ``runner`` on a fresh event loop (helper for scripts and tests)."""
    return asyncio.run(runner.run())
