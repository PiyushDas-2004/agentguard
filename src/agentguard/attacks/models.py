"""Dataset file model and template rendering."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field

from agentguard.core.types import AttackCase

__all__ = ["TEMPLATE_VARIABLES", "AttackPack", "TemplateVars", "render_template"]

TEMPLATE_VARIABLES = ("CANARY", "ATTACKER_ACCOUNT", "EXFIL_URL", "ATTACKER_EMAIL")
_TEMPLATE_RE = re.compile(r"\{\{\s*([A-Z_]+)\s*\}\}")


class AttackPack(BaseModel):
    """One dataset YAML file: pack metadata plus its cases."""

    model_config = ConfigDict(extra="forbid")

    pack: str
    description: str = ""
    version: int = 1
    cases: list[dict[str, object]] = Field(default_factory=list)


class TemplateVars(BaseModel):
    """Values substituted into ``{{VAR}}`` placeholders for one trial."""

    CANARY: str
    ATTACKER_ACCOUNT: str = "ATTACKER-0000"
    EXFIL_URL: str = "https://exfil.attacker.example/collect"
    ATTACKER_EMAIL: str = "drop@attacker.example"

    def mapping(self) -> dict[str, str]:
        """Return the substitution mapping."""
        return {k: str(v) for k, v in self.model_dump().items()}


def render_template(text: str, variables: dict[str, str]) -> str:
    """Substitute ``{{VAR}}`` placeholders; unknown variables are left untouched."""

    def repl(match: re.Match[str]) -> str:
        return variables.get(match.group(1), match.group(0))

    return _TEMPLATE_RE.sub(repl, text)


def template_names(text: str) -> list[str]:
    """Return placeholder names used in ``text``."""
    return _TEMPLATE_RE.findall(text)


def case_text(case: AttackCase) -> str:
    """All attacker-controlled text of a case (used for linting and near-duplicate checks)."""
    parts = [t.content for t in case.turns]
    if case.poison is not None:
        parts.append(case.poison.content)
    return "\n".join(parts)
