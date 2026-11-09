"""Package-hallucination detector: recommended packages that do not exist in the registry snapshot.

The bundled snapshots (``agentguard/data/packages_{pypi,npm}.txt``) hold the 15,000 most
downloaded PyPI projects and ~20,000 popular npm packages (fetched 2026-11-09). A legitimate but
obscure package outside the snapshot would be reported, so verdict confidence is 0.85.
"""

from __future__ import annotations

import re
import sys
from functools import lru_cache
from importlib import resources

from agentguard.core.types import EvidenceSpan, Verdict
from agentguard.detectors.base import DetectionContext, Detector

__all__ = [
    "PackageHallucinationDetector",
    "extract_packages",
    "load_package_index",
    "package_exists",
]

_INSTALL = re.compile(
    r"\b(pip3? install|python -m pip install|poetry add|uv add|pipenv install|conda install|"
    r"npm (?:install|i)|yarn add|pnpm add|bun add)\s+((?:-{1,2}[\w-]+\s+)*)([^\n`;&|]+)",
    re.I,
)
_MENTION = re.compile(r"`([A-Za-z0-9@][A-Za-z0-9._/@\-]{1,80})`\s+(?:package|library|module)\b", re.I)
_JS_INSTALLERS = ("npm", "yarn", "pnpm", "bun")


@lru_cache(maxsize=4)
def load_package_index(ecosystem: str) -> frozenset[str]:
    """Load the bundled package-name snapshot for ``pypi`` or ``npm`` (normalized names)."""
    name = {"pypi": "packages_pypi.txt", "npm": "packages_npm.txt"}[ecosystem]
    text = resources.files("agentguard.data").joinpath(name).read_text(encoding="utf-8")
    names = {line.strip().lower() for line in text.splitlines() if line.strip() and not line.startswith("#")}
    if ecosystem == "pypi":
        names |= {n.replace("_", "-").replace(".", "-") for n in names}
    return frozenset(names)


def _normalize(name: str, ecosystem: str) -> str:
    name = name.strip().strip("'\"`.,").lower()
    name = re.split(r"[=<>!~\[;@ ]", name, maxsplit=1)[0] if ecosystem == "pypi" else re.sub(r"(?<=.)@.*$", "", name)
    if ecosystem == "pypi":
        name = re.sub(r"[_.]+", "-", name)
    return name


def package_exists(name: str, ecosystem: str) -> bool:
    """True if ``name`` is in the snapshot (or the Python stdlib for PyPI)."""
    normalized = _normalize(name, ecosystem)
    if ecosystem == "pypi" and normalized.replace("-", "_") in sys.stdlib_module_names:
        return True
    return normalized in load_package_index(ecosystem)


def extract_packages(text: str) -> list[tuple[str, str, int, int]]:
    """Return ``(name, ecosystem, start, end)`` for packages recommended in ``text``."""
    found: list[tuple[str, str, int, int]] = []
    for match in _INSTALL.finditer(text):
        installer = match.group(1).lower()
        ecosystem = "npm" if installer.startswith(_JS_INSTALLERS) else "pypi"
        args = match.group(3)
        offset = match.start(3)
        for token in re.finditer(r"\S+", args):
            value = token.group(0)
            if (
                value.startswith("-")
                or ("/" in value and not value.startswith("@"))
                or value.startswith(("http", ".", "$"))
            ):
                continue
            if not re.match(r"^[A-Za-z0-9@]", value):
                break
            found.append((value, ecosystem, offset + token.start(), offset + token.end()))
    for match in _MENTION.finditer(text):
        context = text[max(0, match.start() - 120) : match.end() + 60].lower()
        ecosystem = "npm" if re.search(r"\b(npm|node|javascript|typescript|js)\b", context) else "pypi"
        found.append((match.group(1), ecosystem, match.start(1), match.end(1)))
    return found


class PackageHallucinationDetector(Detector):
    """Flags recommended packages that are absent from the registry snapshot."""

    id = "package_halluc"
    description = "The reply recommends packages that do not exist (slopsquatting risk)."

    def detect(self, ctx: DetectionContext) -> Verdict:
        """Check every recommended package name."""
        user_text = ctx.user_text().lower()
        evidence: list[EvidenceSpan] = []
        for index, text in ctx.assistant_turns():
            for name, ecosystem, start, end in extract_packages(text):
                if not package_exists(name, ecosystem):
                    mentioned_by_user = name.lower() in user_text
                    reason = f"{ecosystem} package '{name}' not found in registry snapshot"
                    if mentioned_by_user:
                        reason += " (suggested by the user and endorsed by the agent)"
                    evidence.append(EvidenceSpan(turn_index=index, start=start, end=end, text=name, reason=reason))
        return self.verdict(
            ctx,
            evidence,
            "All recommended packages exist.",
            f"{len(evidence)} hallucinated package(s).",
            confidence=0.85,
        )
