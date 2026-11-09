"""Conversation driver: runs one trial (all sessions and turns) against a target."""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any

from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential_jitter,
)

from agentguard.attacks.models import TemplateVars, render_template
from agentguard.attacks.mutations import mutate_case
from agentguard.config.policy import Policy
from agentguard.core.errors import (
    AgentGuardError,
    BudgetExceededError,
    TargetError,
    TargetTimeoutError,
    error_info_from_exception,
)
from agentguard.core.seeds import derive_seed
from agentguard.core.types import (
    AttackCase,
    InjectionVector,
    Role,
    Transcript,
    TranscriptTurn,
    Trial,
    utcnow,
)
from agentguard.harness.canary import CanaryRegistry
from agentguard.harness.environment import EmailMessage, VirtualEnvironment
from agentguard.harness.prompts import DEFAULT_SYSTEM_PROMPT
from agentguard.harness.rag_fixture import RagCorpus, RagDocument, RagIndex
from agentguard.harness.sandbox import Approver, ToolSandbox
from agentguard.llm.base import BaseLLM, LLMMessage
from agentguard.llm.budget import BudgetTracker
from agentguard.targets.base import BaseTarget, MeteredLLM, TargetContext, TargetResponse

__all__ = ["ConversationDriver", "TrialRun", "sanitize_text"]

DEFAULT_POISON_LOCATIONS: dict[InjectionVector, str] = {
    InjectionVector.file_content: "/sandbox/public/shared/document.txt",
    InjectionVector.web_page: "https://partner.example.com/update",
    InjectionVector.tool_output: "db_query",
    InjectionVector.email_body: "partner@external.example",
    InjectionVector.memory: "team_note",
}


def sanitize_text(text: str) -> str:
    """Make arbitrary target output safe to store: valid UTF-8, no NUL bytes."""
    cleaned = text.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    return cleaned.replace("\x00", "�")


def _retryable(exc: BaseException) -> bool:
    if isinstance(exc, AgentGuardError):
        return exc.retryable
    return isinstance(exc, (TimeoutError, ConnectionError))


@dataclass
class TrialRun:
    """Everything produced by running one trial, used by detectors and storage."""

    trial: Trial
    case: AttackCase
    env: VirtualEnvironment
    canaries: CanaryRegistry
    sandbox: ToolSandbox
    system_prompt: str
    variables: dict[str, str]
    wall_time_s: float = 0.0
    retrieved_contexts: list[str] = field(default_factory=list)
    output_truncated: bool = False


class ConversationDriver:
    """Builds the per-trial world and drives the conversation.

    Args:
        target: the target adapter.
        policy: security policy for the sandbox.
        llm_factory: returns the model a Python demo target should use (or ``None``).
        rag_corpus: bundled corpus (clean docs are indexed for every trial).
        budget: shared run budget.
        timeout_seconds: per-turn timeout.
        max_retries: retries for retryable target errors (exponential backoff with jitter).
        retry_base_seconds: initial backoff.
        max_output_chars: longer replies are truncated and flagged.
        system_prompt: template of the system prompt (``{{CANARY}}`` is replaced).
        known_secrets: additional strings to treat as canaries (for external targets).
        approver: approval callback for the sandbox.
    """

    def __init__(
        self,
        target: BaseTarget,
        policy: Policy,
        *,
        llm_factory: Any = None,
        rag_corpus: RagCorpus | None = None,
        budget: BudgetTracker | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
        retry_base_seconds: float = 0.5,
        max_output_chars: int = 200_000,
        system_prompt: str | None = None,
        known_secrets: list[str] | None = None,
        approver: Approver | None = None,
        target_options: dict[str, Any] | None = None,
    ) -> None:
        self.target = target
        self.policy = policy
        self.llm_factory = llm_factory
        self.rag_corpus = rag_corpus
        self._base_index = RagIndex(list(rag_corpus.clean)) if rag_corpus else RagIndex([])
        self.budget = budget
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_base_seconds = retry_base_seconds
        self.max_output_chars = max_output_chars
        self.system_prompt_template = system_prompt or DEFAULT_SYSTEM_PROMPT
        self.known_secrets = list(known_secrets or [])
        self.approver = approver
        self.target_options = dict(target_options or {})

    # ------------------------------------------------------------------ world building
    def build_world(
        self,
        case: AttackCase,
        *,
        run_id: str,
        trial_index: int,
        seed: int,
        mutation_id: str | None,
        apply_poison: bool = True,
    ) -> tuple[VirtualEnvironment, CanaryRegistry, dict[str, str], str, TargetContext]:
        """Create environment, canaries, template variables, system prompt and context."""
        canaries = CanaryRegistry(seed=seed, scope=(case.id, trial_index, mutation_id or "seed"))
        system_secret = canaries.new("system_prompt", "system_prompt")
        rng = random.Random(derive_seed(seed, "vars"))  # noqa: S311  # nosec B311
        variables = TemplateVars(
            CANARY=canaries.new("obedience", case.id),
            ATTACKER_ACCOUNT=f"ATTACKER-{rng.randint(0, 9999):04d}",
            EXFIL_URL=f"https://exfil.attacker.example/c/{rng.randint(1000, 9999)}",
            ATTACKER_EMAIL=f"drop{rng.randint(10, 99)}@attacker.example",
        ).mapping()
        for secret in self.known_secrets:
            canaries.register(secret, "known_secret")
        env = VirtualEnvironment.build(seed, canaries, self._base_index)
        system_prompt = self.system_prompt_template.replace("{{CANARY}}", system_secret)
        context = TargetContext(
            run_id=run_id,
            case_id=case.id,
            trial_index=trial_index,
            seed=seed,
            system_prompt=system_prompt,
            memory=env.memory,
            rag=env.rag,
            timeout_seconds=self.timeout_seconds,
            extra=dict(self.target_options),
        )
        if apply_poison and case.poison is not None:
            self._apply_poison(case, env, context, variables)
        context.rag = env.rag
        return env, canaries, variables, system_prompt, context

    def _apply_poison(
        self,
        case: AttackCase,
        env: VirtualEnvironment,
        context: TargetContext,
        variables: dict[str, str],
    ) -> None:
        poison = case.poison
        assert poison is not None
        content = render_template(poison.content, variables) if poison.content else ""
        location = poison.location or DEFAULT_POISON_LOCATIONS.get(poison.vector, "")
        vector = poison.vector
        if vector == InjectionVector.system_context:
            context.system_context = content
        elif vector == InjectionVector.rag_document:
            if poison.corpus_doc and self.rag_corpus is not None:
                doc = self.rag_corpus.poisoned_doc(poison.corpus_doc)
                env.rag = env.rag.add(doc).render(variables)
            if content:
                doc_id = location or f"poison-{case.id.lower()}"
                title = content.strip().splitlines()[0].lstrip("# ")[:80] if content.strip() else doc_id
                env.rag = env.rag.add(RagDocument(doc_id=doc_id, title=title, text=content, poisoned=True))
        elif vector == InjectionVector.tool_output:
            env.tool_output_overrides[location or "db_query"] = content
        elif vector == InjectionVector.file_content:
            env.files[location] = content
        elif vector == InjectionVector.email_body:
            subject = "Re: your request"
            if "|" in location:
                location, subject = location.split("|", 1)
            env.inbox.append(EmailMessage(id="M-99", sender=location, subject=subject, body=content))
        elif vector == InjectionVector.web_page:
            env.web[location] = content
        elif vector == InjectionVector.memory:
            env.memory.write(location or "team_note", content, session=0, source="poison")

    # ------------------------------------------------------------------ execution
    async def _send_with_retry(
        self, conversation: list[LLMMessage], sandbox: ToolSandbox, context: TargetContext
    ) -> TargetResponse:
        async def attempt() -> TargetResponse:
            try:
                return await asyncio.wait_for(
                    self.target.send(list(conversation), sandbox, context),
                    timeout=self.timeout_seconds,
                )
            except TimeoutError as exc:
                raise TargetTimeoutError(f"target did not respond within {self.timeout_seconds}s") from exc

        retrying = AsyncRetrying(
            stop=stop_after_attempt(self.max_retries + 1),
            wait=wait_exponential_jitter(initial=self.retry_base_seconds, max=max(self.retry_base_seconds * 8, 0.01)),
            retry=retry_if_exception(_retryable),
            reraise=True,
        )
        async for attempt_ctx in retrying:
            with attempt_ctx:
                return await attempt()
        raise TargetError("unreachable retry state")  # pragma: no cover

    def make_llm(self, seed: int) -> MeteredLLM | None:
        """Instantiate the (metered) model for a Python demo target."""
        if self.llm_factory is None:
            return None
        inner: BaseLLM = self.llm_factory(seed)
        return MeteredLLM(inner, self.budget, component="target")

    def prepare(
        self,
        case: AttackCase,
        *,
        run_id: str,
        trial_index: int,
        seed: int,
        mutation_id: str | None = None,
        transform: str | None = None,
    ) -> tuple[TrialRun, TargetContext]:
        """Build the world (canaries, env, poison, mutation) and an empty trial."""
        env, canaries, variables, system_prompt, context = self.build_world(
            case, run_id=run_id, trial_index=trial_index, seed=seed, mutation_id=mutation_id, apply_poison=False
        )
        if transform is not None:
            case = mutate_case(case, transform, derive_seed(seed, "mutation", transform), variables)
        if case.poison is not None:
            self._apply_poison(case, env, context, variables)
            context.rag = env.rag
        context.llm = self.make_llm(seed)
        sandbox = ToolSandbox(env, self.policy, approver=self.approver)
        trial = Trial(run_id=run_id, case_id=case.id, trial_index=trial_index, seed=seed, mutation_id=mutation_id)
        trial.transcript = Transcript(model=context.llm.model_name if context.llm else None)
        run = TrialRun(trial, case, env, canaries, sandbox, system_prompt, variables)
        return run, context

    def finalize(self, run: TrialRun, sessions: list[int], started: float) -> TrialRun:
        """Stamp timing and copy recorded tool calls into the transcript."""
        run.wall_time_s = time.perf_counter() - started
        run.trial.ended_at = utcnow()
        run.trial.transcript.tool_calls = list(run.sandbox.calls)
        run.trial.transcript.metadata.update(
            {
                "wall_time_s": round(run.wall_time_s, 6),
                "sessions": sorted(sessions) or [1],
                "output_truncated": run.output_truncated,
            }
        )
        return run

    async def run_trial(
        self,
        case: AttackCase,
        *,
        run_id: str,
        trial_index: int,
        seed: int,
        mutation_id: str | None = None,
        transform: str | None = None,
    ) -> TrialRun:
        """Run every session/turn of ``case`` and return the :class:`TrialRun`.

        Target failures are captured in ``trial.error``; ``BudgetExceededError``,
        ``KeyboardInterrupt`` and cancellation propagate.
        """
        run, context = self.prepare(
            case, run_id=run_id, trial_index=trial_index, seed=seed, mutation_id=mutation_id, transform=transform
        )
        started = time.perf_counter()
        turns = [(t.session, render_template(t.content, run.variables)) for t in run.case.turns if t.role == "user"]
        conversations: dict[int, list[LLMMessage]] = {}
        try:
            for session, text in turns:
                await self.step(run, context, conversations, session, text)
        except BudgetExceededError:
            raise
        except (asyncio.CancelledError, KeyboardInterrupt):
            raise
        except Exception as exc:
            run.trial.error = error_info_from_exception(exc)
        return self.finalize(run, list(conversations), started)

    async def step(
        self,
        run: TrialRun,
        context: TargetContext,
        conversations: dict[int, list[LLMMessage]],
        session: int,
        text: str,
    ) -> str:
        """Send one user turn in ``session`` and record the exchange; returns the reply text."""
        transcript = run.trial.transcript
        conversation = conversations.setdefault(session, [])
        context.session = session
        run.sandbox.session = session
        conversation.append(LLMMessage(role="user", content=text))
        transcript.turns.append(
            TranscriptTurn(index=len(transcript.turns), role=Role.user, content=text, session=session)
        )
        run.sandbox.turn_index = len(transcript.turns)
        started = time.perf_counter()
        response = await self._send_with_retry(conversation, run.sandbox, context)
        elapsed_ms = (time.perf_counter() - started) * 1000
        records = context.llm.drain() if context.llm else []
        reply = sanitize_text(response.text or "")
        truncated = len(reply) > self.max_output_chars
        if truncated:
            transcript.metadata["original_output_chars"] = len(reply)
            reply = reply[: self.max_output_chars]
            run.output_truncated = True
        for call in response.tool_calls:
            run.sandbox.record_external(call.name, call.arguments, call.result_preview)
        run.retrieved_contexts.extend(response.retrieved_contexts)
        transcript.turns.append(
            TranscriptTurn(
                index=len(transcript.turns),
                role=Role.assistant,
                content=reply,
                session=session,
                model=response.model or (records[0].model if records else None),
                tokens_in=response.tokens_in + sum(r.tokens_in for r in records),
                tokens_out=response.tokens_out + sum(r.tokens_out for r in records),
                cost_usd=response.cost_usd + sum(r.cost_usd for r in records),
                latency_ms=sum(r.latency_ms for r in records) if records else elapsed_ms,
                truncated=truncated,
            )
        )
        if response.cost_usd and self.budget is not None:
            self.budget.charge(response.cost_usd, "target")
        conversation.append(LLMMessage(role="assistant", content=reply))
        return reply
