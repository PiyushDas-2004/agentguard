"""Lightweight span model: run > case > trial > turn > tool_call / judge_call.

Spans are recorded in-process (for reports and tests). When the optional ``opentelemetry-sdk`` is
installed and an exporter is configured, finished spans are mirrored to OpenTelemetry.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Literal

from pydantic import BaseModel, Field

__all__ = ["Span", "SpanKind", "Tracer"]

SpanKind = Literal["run", "case", "trial", "turn", "tool_call", "judge_call"]

_current_span: ContextVar[Span | None] = ContextVar("agentguard_current_span", default=None)


class Span(BaseModel):
    """A timed unit of work."""

    span_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    parent_id: str | None = None
    kind: SpanKind
    name: str
    start_ns: int = Field(default_factory=time.perf_counter_ns)
    end_ns: int | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    status: Literal["ok", "error"] = "ok"

    @property
    def duration_ms(self) -> float:
        """Span duration in milliseconds (0 while still open)."""
        if self.end_ns is None:
            return 0.0
        return (self.end_ns - self.start_ns) / 1e6


class Tracer:
    """Collects spans and optionally exports them to OpenTelemetry.

    Args:
        otel: export finished spans through the OpenTelemetry API when available.
        max_spans: cap on retained spans to bound memory in long runs.
    """

    def __init__(self, *, otel: bool = False, max_spans: int = 200_000) -> None:
        self.spans: list[Span] = []
        self.max_spans = max_spans
        self.dropped = 0
        self._otel_tracer: Any = None
        if otel:
            self._otel_tracer = self._make_otel_tracer()

    @staticmethod
    def _make_otel_tracer() -> Any:
        try:
            from opentelemetry import trace
        except ImportError:
            return None
        return trace.get_tracer("agentguard")

    @contextmanager
    def span(self, kind: SpanKind, name: str, **attributes: Any) -> Iterator[Span]:
        """Open a child span of the current span for the duration of the ``with`` block."""
        parent = _current_span.get()
        span = Span(kind=kind, name=name, parent_id=parent.span_id if parent else None)
        span.attributes.update(attributes)
        token = _current_span.set(span)
        try:
            yield span
        except BaseException:
            span.status = "error"
            raise
        finally:
            span.end_ns = time.perf_counter_ns()
            try:
                _current_span.reset(token)
            except ValueError:  # finalized from another context (e.g. a cancelled task on 3.11)
                _current_span.set(parent)
            self._record(span)

    def _record(self, span: Span) -> None:
        if len(self.spans) < self.max_spans:
            self.spans.append(span)
        else:
            self.dropped += 1
        if self._otel_tracer is not None:
            with self._otel_tracer.start_as_current_span(f"{span.kind}:{span.name}") as otel_span:
                for key, value in span.attributes.items():
                    if isinstance(value, (str, bool, int, float)):
                        otel_span.set_attribute(f"agentguard.{key}", value)
                otel_span.set_attribute("agentguard.duration_ms", span.duration_ms)

    def by_kind(self, kind: SpanKind) -> list[Span]:
        """Return recorded spans of the given kind."""
        return [s for s in self.spans if s.kind == kind]
