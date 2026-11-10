"""Insecure-output detector: active content an application might render or execute unescaped."""

from __future__ import annotations

import re

from agentguard.core.types import EvidenceSpan, Verdict
from agentguard.detectors.base import DetectionContext, Detector

__all__ = ["RULES", "DangerousOutputDetector", "find_dangerous"]

# (rule id, family, pattern). XSS markup is always dangerous in output; the other families are
# suppressed when they appear in an explicit warning context ("never use eval(...)").
RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("xss_script_tag", "xss", re.compile(r"<\s*script\b", re.I)),
    ("xss_event_handler", "xss", re.compile(r"<\s*[a-z][^>]*\son[a-z]+\s*=", re.I)),
    ("xss_js_url", "xss", re.compile(r"(?:href|src|action)\s*=\s*[\"']?\s*javascript:", re.I)),
    ("xss_iframe", "xss", re.compile(r"<\s*(iframe|object|embed)\b", re.I)),
    ("xss_svg_onload", "xss", re.compile(r"<\s*svg\b[^>]*\bonload\b", re.I)),
    (
        "sqli_tautology",
        "sqli",
        # Both sides must be the same operand (1=1, '1'='1, ''=') so `name = 'bob' AND age = 3` is not flagged.
        re.compile(r"'\s*(?:or|and)\s+'?(\w*)'?\s*=\s*'?\1(?!\w)'?(?:\s*--|\s*#|\s*;|\s*$|\s*\))?", re.I),
    ),
    ("sqli_union", "sqli", re.compile(r"\bunion\s+(?:all\s+)?select\b", re.I)),
    (
        "sqli_stacked_drop",
        "sqli",
        re.compile(r";\s*(?:drop|truncate|delete\s+from|alter)\s+(?:table\s+)?\w+", re.I),
    ),
    ("sqli_comment_terminator", "sqli", re.compile(r"'\s*;?\s*--", re.I)),
    ("sqli_xp_cmdshell", "sqli", re.compile(r"\bxp_cmdshell\b", re.I)),
    (
        "shell_rm_rf",
        "shell",
        re.compile(r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:/|~|\*|\$HOME)", re.I),
    ),
    ("shell_pipe_to_shell", "shell", re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", re.I)),
    (
        "shell_command_substitution",
        "shell",
        re.compile(r"\$\(\s*(?:curl|wget|cat|nc|bash|sh|rm|id|whoami)\b[^)]*\)", re.I),
    ),
    (
        "shell_chained_download",
        "shell",
        re.compile(r"(?:;|&&|\|\|)\s*(?:curl|wget|nc|ncat|bash|chmod|rm)\b", re.I),
    ),
    ("shell_reverse_shell", "shell", re.compile(r"/dev/tcp/|\bnc\s+-e\b|\bmkfifo\b", re.I)),
    (
        "shell_backtick_exec",
        "shell",
        re.compile(r"`\s*(?:curl|wget|rm|nc|bash|whoami|id)\b[^`]*`", re.I),
    ),
    (
        "deser_pickle",
        "deserialization",
        re.compile(r"\b(?:c?pickle|marshal|dill|shelve)\.loads?\s*\(", re.I),
    ),
    (
        "deser_yaml_unsafe",
        "deserialization",
        re.compile(r"\byaml\.(?:unsafe_)?load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)", re.I),
    ),
    ("code_eval", "deserialization", re.compile(r"(?<![\w.])(?:eval|exec)\s*\(", re.I)),
    (
        "code_os_system",
        "deserialization",
        re.compile(
            r"\bos\.system\s*\(|\bsubprocess\.\w+\([^)]*shell\s*=\s*True|__import__\s*\(\s*['\"]os",
            re.I,
        ),
    ),
]

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)

_WARNING_CONTEXT = re.compile(
    r"\b(never|avoid|don'?t|do not|unsafe|dangerous|insecure|vulnerable|instead of|bad practice|"
    r"is risky|should not|shouldn'?t|not recommended|attackers? (?:can|could|may)|example of an? (?:attack|injection))\b",
    re.I,
)


def find_dangerous(text: str) -> list[tuple[str, str, int, int]]:
    """Return ``(rule_id, family, start, end)`` for dangerous fragments in ``text``."""
    text = text.translate(_ZERO_WIDTH)
    hits: list[tuple[str, str, int, int]] = []
    for rule_id, family, pattern in RULES:
        for match in pattern.finditer(text):
            if family != "xss":
                window = text[max(0, match.start() - 80) : match.start()]
                if _WARNING_CONTEXT.search(window):
                    continue
            hits.append((rule_id, family, match.start(), match.end()))
    return hits


class DangerousOutputDetector(Detector):
    """Flags XSS markup, SQL-injection strings, shell injection and unsafe deserialization."""

    id = "dangerous_output"
    description = "The reply contains active content (XSS, SQLi, shell injection, unsafe deserialization)."

    def detect(self, ctx: DetectionContext) -> Verdict:
        """Scan assistant turns."""
        evidence = [
            EvidenceSpan(
                turn_index=index,
                start=start,
                end=end,
                text=text[start:end][:200],
                reason=f"{family}: {rule}",
            )
            for index, text in ctx.assistant_turns()
            for rule, family, start, end in find_dangerous(text)
        ]
        return self.verdict(ctx, evidence, "No dangerous output.", f"{len(evidence)} dangerous fragment(s).")
