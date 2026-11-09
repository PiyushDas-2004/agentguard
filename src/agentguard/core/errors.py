"""Error hierarchy and CLI exit codes."""

from __future__ import annotations

import asyncio
from enum import IntEnum

from agentguard.core.types import ErrorInfo

__all__ = [
    "AgentGuardError",
    "BudgetExceededError",
    "ConfigError",
    "DatasetError",
    "ExitCode",
    "JudgeError",
    "ReportWriteError",
    "StorageError",
    "TargetError",
    "TargetTimeoutError",
    "error_info_from_exception",
]


class ExitCode(IntEnum):
    """Process exit codes of the ``agentguard`` CLI."""

    OK = 0
    RISK_ABOVE_THRESHOLD = 1
    CONFIG_ERROR = 2
    RUNTIME_ERROR = 3
    BUDGET_EXCEEDED = 4


class AgentGuardError(Exception):
    """Base class for all AgentGuard errors.

    Attributes:
        retryable: whether retrying the failed operation may succeed.
    """

    retryable: bool = False

    def __init__(self, message: str, *, retryable: bool | None = None) -> None:
        super().__init__(message)
        self.message = message
        if retryable is not None:
            self.retryable = retryable


class ConfigError(AgentGuardError):
    """Invalid configuration; message names the YAML path and a fix hint."""


class DatasetError(AgentGuardError):
    """Invalid dataset file or case."""


class TargetError(AgentGuardError):
    """The target failed (exception, HTTP error, malformed response).

    Attributes:
        status_code: HTTP status code if the failure came from an HTTP response.
    """

    def __init__(self, message: str, *, retryable: bool | None = None, status_code: int | None = None) -> None:
        super().__init__(message, retryable=retryable)
        self.status_code = status_code


class TargetTimeoutError(TargetError):
    """The target did not answer within the per-turn timeout."""

    retryable = True


class JudgeError(AgentGuardError):
    """The judge could not produce a valid verdict."""


class BudgetExceededError(AgentGuardError):
    """The run's hard cost cap (``max_cost_usd``) was reached."""


class StorageError(AgentGuardError):
    """Persisting results failed."""


class ReportWriteError(AgentGuardError):
    """Writing a report to disk failed (for example, the disk is full)."""


def error_info_from_exception(exc: BaseException) -> ErrorInfo:
    """Convert an exception into a structured :class:`ErrorInfo`.

    Args:
        exc: the exception raised while running a trial.

    Returns:
        An ``ErrorInfo`` with the exception type, a bounded message and retryability.
    """
    if isinstance(exc, AgentGuardError):
        retryable = exc.retryable
    elif isinstance(exc, (TimeoutError, asyncio.TimeoutError, ConnectionError)):
        retryable = True
    else:
        retryable = False
    message = str(exc) or exc.__class__.__name__
    return ErrorInfo(type=exc.__class__.__name__, message=message[:2000], retryable=retryable)
