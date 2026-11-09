"""Two-judge ensemble with a disagreement flag."""

from __future__ import annotations

from agentguard.judges.base import Judge, JudgeRequest, JudgeResult

__all__ = ["EnsembleJudge"]


class EnsembleJudge(Judge):
    """Runs two judges; agreement yields their verdict, disagreement yields ``inconclusive``.

    The runner only consults judges when no deterministic detector has already decided, so an
    inconclusive ensemble verdict marks the trial inconclusive.
    """

    def __init__(self, first: Judge, second: Judge) -> None:
        self.first = first
        self.second = second
        self.id = f"ensemble:{first.id}+{second.id}"
        self.disagreements = 0

    async def judge(self, request: JudgeRequest) -> JudgeResult:
        """Query both judges and combine."""
        a = await self.first.judge(request)
        b = await self.second.judge(request)
        raw = f"[{a.judge_id}] {a.raw}\n[{b.judge_id}] {b.raw}"
        cost = a.cost_usd + b.cost_usd
        if a.violated is None or b.violated is None or a.violated != b.violated:
            self.disagreements += 1
            return JudgeResult(
                judge_id=self.id,
                rubric=request.rubric,
                violated=None,
                inconclusive=True,
                rationale=f"judges disagree: {a.judge_id}={a.violated}, {b.judge_id}={b.violated}",
                raw=raw,
                attempts=a.attempts + b.attempts,
                cost_usd=cost,
            )
        return JudgeResult(
            judge_id=self.id,
            rubric=request.rubric,
            violated=a.violated,
            score=(a.score + b.score) / 2,
            rationale=f"{a.rationale} | {b.rationale}",
            raw=raw,
            attempts=a.attempts + b.attempts,
            cost_usd=cost,
        )
