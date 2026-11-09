"""Hard cost cap shared by every LLM call in a run."""

from __future__ import annotations

from dataclasses import dataclass, field

from agentguard.core.errors import BudgetExceededError

__all__ = ["MOCK_PRICING", "BudgetTracker"]

# Synthetic USD prices per 1M tokens used by MockLLM so offline runs exercise cost accounting.
MOCK_PRICING: dict[str, tuple[float, float]] = {
    "mock": (0.50, 1.50),
}


@dataclass
class BudgetTracker:
    """Accumulates spend and raises :class:`BudgetExceededError` once the cap is crossed.

    Attributes:
        max_cost_usd: hard cap; ``None`` or ``<= 0`` disables the cap.
        spent_usd: total recorded spend.
        calls: number of charged calls.
    """

    max_cost_usd: float | None = None
    spent_usd: float = 0.0
    calls: int = 0
    by_component: dict[str, float] = field(default_factory=dict)
    exceeded: bool = False

    @property
    def remaining(self) -> float | None:
        """Remaining budget in USD, or ``None`` when uncapped."""
        if not self.max_cost_usd or self.max_cost_usd <= 0:
            return None
        return max(0.0, self.max_cost_usd - self.spent_usd)

    def charge(self, cost_usd: float, component: str = "target") -> None:
        """Record spend; raise once the cap is exceeded.

        Args:
            cost_usd: cost of the call just made (must be >= 0).
            component: label for the spend breakdown (``target``, ``judge``, ``attacker``).

        Raises:
            BudgetExceededError: when total spend is above ``max_cost_usd``.
        """
        if cost_usd < 0:
            raise ValueError("cost must be non-negative")
        self.spent_usd += cost_usd
        self.calls += 1
        self.by_component[component] = self.by_component.get(component, 0.0) + cost_usd
        self.check()

    def check(self) -> None:
        """Raise :class:`BudgetExceededError` if the cap has been exceeded."""
        if self.max_cost_usd and self.max_cost_usd > 0 and self.spent_usd > self.max_cost_usd:
            self.exceeded = True
            raise BudgetExceededError(f"budget exceeded: spent ${self.spent_usd:.4f} > cap ${self.max_cost_usd:.4f}")
