"""Run the quality suite (tool-use tasks + RAG QA) through the same conversation driver."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agentguard.config.policy import Policy
from agentguard.core.scheduler import TrialScheduler
from agentguard.core.seeds import derive_seed
from agentguard.core.types import (
    AttackCase,
    AttackCategory,
    InjectionVector,
    Objective,
    ObjectiveType,
    QualityReport,
    Severity,
    Trial,
    Turn,
)
from agentguard.harness.conversation import ConversationDriver, TrialRun
from agentguard.judges.base import Judge, JudgeRequest
from agentguard.quality.consistency import consistency
from agentguard.quality.datasets import QualityTask, RagQuestion, load_rag_questions, load_tasks
from agentguard.quality.deepeval_adapter import evaluate_deepeval
from agentguard.quality.performance import performance_report
from agentguard.quality.rag_metrics import (
    answer_relevancy,
    context_precision,
    context_recall,
    faithfulness,
    retrieved_doc_ids,
)
from agentguard.quality.ragas_adapter import RagSample, evaluate_ragas
from agentguard.quality.task_success import check_success
from agentguard.quality.trajectory import score_trajectory

if TYPE_CHECKING:
    from agentguard.core.runner import Runner

__all__ = ["carrier_case", "run_quality_suite"]


def carrier_case(item_id: str, prompt: str) -> AttackCase:
    """Wrap a quality prompt in an ``AttackCase`` so it runs through the conversation driver."""
    return AttackCase(
        id=item_id,
        category=AttackCategory.OVER_REFUSAL,
        title=f"quality item {item_id}",
        description="Quality-suite carrier case (not scored as security).",
        severity=Severity.info,
        vector=InjectionVector.user_message,
        turns=[Turn(content=prompt)],
        objective=Objective(type=ObjectiveType.answered, description="answer the request"),
        detectors=["refusal"],
        mutations_allowed=False,
    )


@dataclass(frozen=True)
class _Job:
    kind: str
    item: QualityTask | RagQuestion
    index: int


def _reply(run: TrialRun) -> str:
    return run.trial.transcript.assistant_text()


async def run_quality_suite(runner: Runner, driver: ConversationDriver, policy: Policy, judge: Judge) -> QualityReport:
    """Execute tasks and RAG questions ``trials`` times each and compute quality metrics."""
    config = runner.config.suites.quality
    assert config is not None
    trials = config.trials_per_task or runner.options.trials or runner.config.run.trials_per_case
    tasks = load_tasks(runner._path(config.tasks)) if config.tasks else []
    questions = load_rag_questions(runner._path(config.rag)) if config.rag else []
    jobs = [_Job("task", t, i) for t in tasks for i in range(trials)]
    jobs += [_Job("rag", q, i) for q in questions for i in range(trials)]
    seed = runner.config.run.seed

    async def work(job: _Job) -> tuple[_Job, TrialRun]:
        prompt = job.item.goal if isinstance(job.item, QualityTask) else job.item.question
        case = carrier_case(job.item.id, prompt)
        run = await driver.run_trial(
            case, run_id=runner.run_id, trial_index=job.index, seed=derive_seed(seed, "quality", job.item.id, job.index)
        )
        return job, run

    scheduler: TrialScheduler = TrialScheduler(runner.config.run.concurrency)
    outcome = await scheduler.run(jobs, work)
    if outcome.aborted == "budget" and outcome.error is not None:
        raise outcome.error
    by_item: dict[str, list[TrialRun]] = defaultdict(list)
    for job, run in sorted(outcome.results, key=lambda r: (r[0].item.id, r[0].index)):
        by_item[job.item.id].append(run)

    report = QualityReport(n_tasks=len(tasks))
    all_trials: list[Trial] = [run.trial for runs in by_item.values() for run in runs]
    task_metrics: dict[str, list[float]] = defaultdict(list)
    successes: list[bool] = []
    exact_rates: list[float] = []
    jaccards: list[float] = []
    for task in tasks:
        runs = by_item.get(task.id, [])
        task_successes: list[bool] = []
        for run in runs:
            calls = run.trial.transcript.tool_calls
            score = score_trajectory(task.expected_trajectory, calls)
            for name in ("precision", "recall", "f1", "argument_correctness"):
                task_metrics[name].append(getattr(score, name))
            task_metrics["exact_match"].append(float(score.exact_match))
            task_metrics["in_order_match"].append(float(score.in_order_match))
            task_metrics["any_order_match"].append(float(score.any_order_match))
            task_metrics["unnecessary_calls"].append(float(score.unnecessary_calls))
            ok = check_success(task, _reply(run), calls)
            if ok is None:
                result = await judge.judge(
                    JudgeRequest(
                        rubric="task_success", user_input=task.goal, response=_reply(run), reference=task.reference
                    )
                )
                ok = result.violated is False
            task_successes.append(ok and run.trial.error is None)
        exact, jac = consistency([_reply(r) for r in runs])
        exact_rates.append(exact)
        jaccards.append(jac)
        successes.extend(task_successes)
        report.per_task.append(
            {
                "id": task.id,
                "goal": task.goal,
                "success_rate": round(sum(task_successes) / len(task_successes), 4) if task_successes else 0.0,
                "consistency_exact": exact,
                "consistency_jaccard": jac,
            }
        )
    report.task_success_rate = round(sum(successes) / len(successes), 4) if successes else None
    report.trajectory = {k: round(sum(v) / len(v), 4) for k, v in sorted(task_metrics.items()) if v}

    rag_scores: dict[str, list[float]] = defaultdict(list)
    samples: list[RagSample] = []
    for question in questions:
        runs = by_item.get(question.id, [])
        per_q: dict[str, list[float]] = defaultdict(list)
        for run in runs:
            answer = _reply(run)
            contexts = list(run.retrieved_contexts) or [
                c.result_preview for c in run.trial.transcript.tool_calls if c.name == "search_docs"
            ]
            values = {
                "faithfulness": faithfulness(answer, contexts),
                "answer_relevancy": answer_relevancy(answer, question.question),
                "context_precision": context_precision(retrieved_doc_ids(contexts), question.relevant_docs),
                "context_recall": context_recall(question.reference_answer, contexts),
            }
            for key, value in values.items():
                per_q[key].append(value)
                rag_scores[key].append(value)
            samples.append(RagSample(question.question, answer, contexts, question.reference_answer))
        exact, jac = consistency([_reply(r) for r in runs])
        exact_rates.append(exact)
        jaccards.append(jac)
        report.per_question.append(
            {
                "id": question.id,
                "question": question.question,
                **{k: round(sum(v) / len(v), 4) for k, v in per_q.items() if v},
            }
        )
    report.rag = {k: round(sum(v) / len(v), 4) for k, v in sorted(rag_scores.items()) if v}
    if exact_rates:
        report.consistency = {
            "exact_match": round(sum(exact_rates) / len(exact_rates), 4),
            "token_jaccard": round(sum(jaccards) / len(jaccards), 4),
        }
    report.backends["builtin"] = {
        **report.rag,
        **({"task_success_rate": report.task_success_rate} if report.task_success_rate is not None else {}),
    }
    for backend in config.backends:
        if backend == "builtin":
            continue
        evaluate: Any = evaluate_ragas if backend == "ragas" else evaluate_deepeval
        result = evaluate(samples, offline=runner.offline)
        if result.scores:
            report.backends[backend] = result.scores
        if result.message:
            report.backend_messages.append(result.message)
    report.performance = performance_report(all_trials)
    return report
