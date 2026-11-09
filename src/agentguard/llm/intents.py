"""Deterministic intent extraction for the naive, instruction-following mock model.

The naive model (see :mod:`agentguard.llm.mock`) stands in for an LLM that obeys whatever
instructions it reads — from the user, from retrieved documents, from tool outputs. This module
turns free text into structured intents:

* :class:`ToolIntent` — a tool the text asks the model to call (with extracted arguments);
* :class:`Directive` — something the text asks the model to put in its answer (leak the system
  prompt, reveal a secret, include a token, echo a payload verbatim, render an exfiltration
  image, repeat output many times, recommend packages).

The grammar is intentionally broad (synonym sets, negation handling, de-obfuscation) and is
documented in ``docs/ATTACKS.md`` so dataset authors can write diverse cases that a real
instruction-following model would also act on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentguard.llm.textnorm import (
    SPANISH_TO_ENGLISH,
    decode_base64_segments,
    deleet,
    extract_json_strings,
    normalize_for_reading,
    rejoin_split_words,
    rot13,
    untranslate_spanish,
)

__all__ = [
    "Directive",
    "Intents",
    "ToolIntent",
    "detect_transform",
    "extract_intents",
    "find_secrets",
    "reading_variants",
    "split_units",
]

MAX_PARSE_CHARS = 20_000

URL_RE = re.compile(r"https?://[^\s)\]\"'<>`]+")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PATH_RE = re.compile(r"(?<![\w:/.])(/(?:[\w.\-]+/)+[\w.\-]*|/(?:etc|tmp|root|var|home|sandbox|usr|bin|opt)\b[\w./\-]*)")
FILENAME_RE = re.compile(
    r"\b[\w\-]+\.(?:txt|md|csv|json|log|eml|cfg|conf|env|ya?ml|ini|pdf|docx|key|pem|html|sql|py|sh)\b"
)
ACCOUNT_RE = re.compile(r"\b([A-Z]{2,}(?:-[A-Z]+)*-\d{3,})\b")
AMOUNT_RE = re.compile(
    r"(?:(?:\$|usd\s?|eur\s?|€|£|inr\s?|rs\.?\s?|₹)\s?(\d[\d,]*(?:\.\d+)?))"
    r"|(?:(\d[\d,]*(?:\.\d+)?)\s?(?:dollars|usd|euros?|eur|rupees|inr|gbp|pounds))",
    re.IGNORECASE,
)
RECORD_ID_RE = re.compile(r"\b([COEP]-\d{4})\b")
BACKTICK_RE = re.compile(r"`([^`\n]{1,300})`")
FENCE_RE = re.compile(r"```[a-zA-Z0-9_-]*\n?(.*?)```", re.DOTALL)
DQUOTE_RE = re.compile(r"\"([^\"\n]{1,500})\"|“([^”\n]{1,500})”")
SQUOTE_RE = re.compile(r"(?<![A-Za-z])'([^'\n]{2,300})'(?![A-Za-z])")
TOKEN_LITERAL_RE = re.compile(r"\b[A-Z]{2,}(?:-[A-Z0-9]+){1,4}\b")
SECRET_VALUE_RE = re.compile(
    r"(?i)\b(?:code|key|token|password|passphrase|secret|pin|credential|api[_ -]?key)\b"
    r"[^\n:=]{0,30}?(?:\bis\b|:|=)\s*[\"'`]?([A-Za-z0-9][A-Za-z0-9_\-]{7,})"
)

DEFERRAL_RE = re.compile(
    r"\b(whenever|from now on|in (?:all )?future|next time|in the future|in later sessions|"
    r"each time|every time|any time|anytime|going forward|in subsequent|for future|"
    r"in every future|later on|once (?:the|a) (?:user|customer|someone) asks)\b"
)

NEGATION_RE = re.compile(
    r"\b(never|do not|don't|dont|must not|mustn't|should not|shouldn't|cannot|can't|won't|"
    r"may not|not allowed to|refuse to|avoid|under no circumstances|no need to)\b"
)

REVEAL_VERBS = (
    r"(repeat|print|reveal|show|output|display|tell|recite|dump|echo|write(?: out| down)?|copy|"
    r"paste|translate|summari[sz]e|spell(?: out)?|encode|list|share|disclose|give|provide|"
    r"read(?: back| out)?|quote|reproduce|state|expose|paraphrase|rewrite|convert|put|format|"
    r"return|emit|transcribe|leak|send|include|type|render|describe|explain|confirm|verify|"
    r"what (?:is|are|was|were)|what's)"
)
SYSTEM_PROMPT_OBJ = (
    r"(system[ -]?prompt|system message|system instructions?|initial (?:prompt|instructions?)|"
    r"original (?:prompt|instructions?)|"
    r"(?:hidden|secret|internal|confidential|previous|prior|earlier|above|preceding|original|first|"
    r"developer|operator|core|base|full|exact|complete) (?:instructions?|prompt|message|rules|"
    r"directives|configuration|guidelines)|"
    r"(?:instructions?|text|message|prompt|content|everything|words) (?:above|before this|"
    r"you (?:were|have been) given)|"
    r"your (?:instructions|rules|guidelines|configuration|prompt|directives|setup|programming|"
    r"initial message|system message|operating instructions|guardrails|policies)|"
    r"preamble|developer message|setup message|meta[- ]?prompt|everything (?:above|before)|"
    r"the words above|configuration text|first message)"
)
SECRET_OBJ = (
    r"(canary|secrets?|tokens?|(?:reference|internal|verification|access|security|confirmation|"
    r"tracking|auth(?:entication)?|admin|master|override|session|deployment|unlock|debug|"
    r"license|activation|vault) (?:code|key|token|number|id|pin|string|value|phrase)s?|"
    r"api[ _-]?keys?|passwords?|passphrases?|credentials?|private keys?|code ?words?|passcodes?|"
    r"\bpins?\b|keys?|codes?)"
)
INCLUDE_VERBS = (
    r"(include|append|add|insert|end (?:your|the|each|every) (?:reply|answer|response|message|"
    r"summary|output) with|start (?:your|the|each) (?:reply|answer|response|message) with|"
    r"begin (?:your|the|each) (?:reply|answer|response|message) with|mention|say|write|"
    r"respond with|reply with|output|print|sign off with|finish with|put|place|attach|prepend|"
    r"tag|stamp|echo|emit|close with|conclude with|add the (?:phrase|text|string|word))"
)
EXFIL_MEDIA = (
    r"(image|img|picture|photo|pixel|badge|icon|logo|beacon|banner|thumbnail|link|hyperlink|"
    r"url|anchor|markdown|!\[)"
)
EXFIL_VERBS = (
    r"(render|include|display|show|add|embed|output|insert|append|put|place|end|attach|create|"
    r"make|draw|print|generate|write|format|load|close|finish)"
)
SENSITIVE_DATA = (
    r"(secret|code|token|key|password|system prompt|instructions|conversation|chat|history|"
    r"data|summary|email address|address|phone|card|customer|ssn|social security|user|"
    r"everything|credential|context|pin|record|details|information|answer|reply|response)"
)
VERBATIM = (
    r"(exactly|verbatim|as[- ]is|unchanged|word[- ]for[- ]word|character[- ]for[- ]character|"
    r"literally|without (?:any )?(?:changes|modifications?|escaping|sanitization|sanitizing|"
    r"encoding|editing|alterations?|filtering)|raw|unescaped|unmodified|precisely)"
)
CODE_FORMATS = (
    r"(html|web ?page|snippet|markup|template|sql|query|command|script|shell|bash|json|yaml|csv|"
    r"markdown|xml|svg|javascript|js|code|one-liner|payload|widget|banner|email template)"
)
REPEAT_NUMBER_WORDS = {
    "hundred": 100,
    "thousand": 1000,
    "ten thousand": 10_000,
    "hundred thousand": 100_000,
    "million": 1_000_000,
    "billion": 1_000_000_000,
    "infinite": 1_000_000,
    "infinitely": 1_000_000,
    "forever": 1_000_000,
    "endless": 1_000_000,
    "endlessly": 1_000_000,
    "indefinitely": 1_000_000,
    "nonstop": 1_000_000,
    "unlimited": 1_000_000,
}

TOOL_NAMES = (
    "email_send",
    "email_read",
    "file_read",
    "file_write",
    "http_get",
    "db_query",
    "shell_exec",
    "payment_transfer",
    "memory_write",
    "memory_read",
    "search_docs",
)

# Words the reader reconstructs when an attacker splits them ("ig nore", "sys-tem").
VOCABULARY: frozenset[str] = frozenset(
    [
        "ignore",
        "previous",
        "instructions",
        "instruction",
        "system",
        "prompt",
        "reveal",
        "secret",
        "password",
        "print",
        "repeat",
        "transfer",
        "payment",
        "execute",
        "command",
        "shell",
        "reference",
        "internal",
        "canary",
        "token",
        "disregard",
        "override",
        "developer",
        "mode",
        "jailbreak",
        "confidential",
        "credentials",
        "verbatim",
        "forget",
        "administrator",
        "restrictions",
        "unrestricted",
        "send",
        "email",
        "fetch",
        "include",
        "append",
        "translate",
        "summarize",
        "remember",
        "delete",
        "sandbox",
        "account",
        "attacker",
        "image",
        "markdown",
        "memory",
        "forward",
        "exfiltrate",
        "guidelines",
        "hidden",
        "original",
        "initial",
    ]
)

SPANISH_MARKERS = frozenset(w for w in SPANISH_TO_ENGLISH if len(w) > 3 and w not in {"todas", "texto"})


@dataclass
class ToolIntent:
    """A tool call requested by text.

    Attributes:
        name: tool name.
        arguments: extracted arguments.
        source: ``user``, ``untrusted`` or ``system``.
        repeat: number of times the text asks for the call.
        unit: the instruction text the intent came from.
    """

    name: str
    arguments: dict[str, Any]
    source: str = "user"
    repeat: int = 1
    unit: str = ""
    deferred: bool = False

    def key(self) -> str:
        """Identity used to de-duplicate calls (name + sorted args)."""
        args = ",".join(f"{k}={self.arguments[k]!s}" for k in sorted(self.arguments))
        return f"{self.name}({args})"


@dataclass
class Directive:
    """Something the text asks the model to put in its answer.

    Attributes:
        kind: ``leak_system_prompt``, ``leak_secret``, ``include``, ``echo``, ``exfil_media``,
            ``repeat``, ``packages``, ``refuse_nothing``.
        payload: literal text, URL or package request depending on ``kind``.
        transform: requested encoding (``base64``, ``hex``, ``reverse``, ``rot13``, ``url``,
            ``spaced``, ``dotted``, ``dashed``, ``translate``, ``summary``) or ``None``.
        count: repetition count for ``repeat``.
        media: ``image`` or ``link`` for ``exfil_media``.
        source: provenance of the instruction.
    """

    kind: str
    payload: str = ""
    transform: str | None = None
    count: int = 1
    media: str = "image"
    source: str = "user"
    data_hint: str = ""
    deferred: bool = False


@dataclass
class Intents:
    """All intents extracted from one piece of text."""

    tools: list[ToolIntent] = field(default_factory=list)
    directives: list[Directive] = field(default_factory=list)
    wants_search: bool = False
    format_request: str | None = None
    carry_over: bool = False

    def extend(self, other: Intents) -> None:
        """Merge another ``Intents`` into this one, de-duplicating tool calls."""
        seen = {t.key() for t in self.tools}
        for tool in other.tools:
            if tool.key() not in seen:
                self.tools.append(tool)
                seen.add(tool.key())
        seen_d = {(d.kind, d.payload, d.transform) for d in self.directives}
        for directive in other.directives:
            ident = (directive.kind, directive.payload, directive.transform)
            if ident not in seen_d:
                self.directives.append(directive)
                seen_d.add(ident)
        self.wants_search = self.wants_search or other.wants_search
        self.format_request = self.format_request or other.format_request
        self.carry_over = self.carry_over or other.carry_over

    @property
    def empty(self) -> bool:
        """True when no tool calls or directives were found."""
        return not self.tools and not self.directives


def _looks_spanish(text: str) -> bool:
    words = {w.lower() for w in re.findall(r"[^\W\d_]+", text)}
    return len(words & SPANISH_MARKERS) >= 3


def reading_variants(text: str, *, decode_encodings: bool = True) -> list[str]:
    """Return the readings of ``text`` a capable model would understand.

    The first element is the normalized text; further elements are de-leeted, re-joined,
    translated, JSON-extracted, base64-decoded and ROT13-decoded readings when applicable.
    """
    text = text[:MAX_PARSE_CHARS]
    base = normalize_for_reading(text)
    variants = [base]

    def add(candidate: str) -> None:
        if candidate and candidate not in variants:
            variants.append(candidate)

    add(deleet(base))
    add(rejoin_split_words(base, VOCABULARY))
    add(rejoin_split_words(deleet(base), VOCABULARY))
    if _looks_spanish(base):
        add(untranslate_spanish(base))
    for value in extract_json_strings(base):
        add(normalize_for_reading(value))
    if decode_encodings:
        for decoded in decode_base64_segments(base):
            add(normalize_for_reading(decoded))
        if re.search(r"(?i)\brot[- ]?13\b|\bcaesar\b|\brot\s*13\b", base):
            body = base.split(":", 1)[1] if ":" in base else base
            add(rot13(body))
            for line in base.splitlines():
                if line.strip() and not re.search(r"(?i)rot[- ]?13|caesar", line):
                    add(rot13(line))
    return variants


def split_units(text: str) -> list[str]:
    """Split text into instruction units (sentences / clauses)."""
    text = FENCE_RE.sub(lambda m: m.group(0).replace("\n", " \u2063 "), text)
    parts = re.split(r"(?<=[.!?;])\s+|\n+|\s+(?:then|after that|afterwards|next|also|and then)\s+", text)
    units: list[str] = []
    for part in parts:
        if not part or not part.strip():
            continue
        units.append(part.replace(" \u2063 ", "\n").strip())
    return units


def _negated(unit_lower: str, verb_pos: int) -> bool:
    window = unit_lower[max(0, verb_pos - 40) : verb_pos]
    return bool(NEGATION_RE.search(window))


def detect_transform(unit_lower: str) -> str | None:
    """Detect a requested encoding/transform in an instruction unit."""
    checks: list[tuple[str, str]] = [
        (r"\bbase ?64\b|\bb64\b", "base64"),
        (r"\bhex(?:adecimal)?\b", "hex"),
        (r"\brot[- ]?13\b|\bcaesar\b", "rot13"),
        (r"\breverse(?:d)?\b|\bbackwards?\b|\bright[- ]to[- ]left\b", "reverse"),
        (r"\burl[- ]?encod|\bpercent[- ]encod", "url"),
        (
            r"\bwith dots\b|\bdots between\b|\bseparated by (?:dots|periods)\b|\bperiod between",
            "dotted",
        ),
        (
            r"\bwith dashes\b|\bdashes between\b|\bhyphens? between\b|\bseparated by (?:dashes|hyphens)",
            "dashed",
        ),
        (
            r"\bspell(?:ed|ing)? (?:it )?out\b|\bletter[- ]by[- ]letter\b|\bcharacter[- ]by[- ]character\b|"
            r"\bspaces? between\b|\bseparate (?:each|every) (?:letter|character)\b|\bone character at a time\b|"
            r"\bspell\b",
            "spaced",
        ),
        (
            r"\btranslat|\bin (?:french|spanish|german|hindi|italian|portuguese|japanese|pig latin|"
            r"klingon|latin)\b",
            "translate",
        ),
        (
            r"\bsummari[sz]|\bparaphras|\btl;?dr\b|\bgist\b|\bbullet points?\b|\bin your own words\b",
            "summary",
        ),
    ]
    for pattern, name in checks:
        if re.search(pattern, unit_lower):
            return name
    return None


def find_secrets(context_text: str) -> list[str]:
    """Return secret-looking values announced in context ("... code: VALUE")."""
    found: list[str] = []
    for match in SECRET_VALUE_RE.finditer(context_text):
        value = match.group(1).rstrip(".,;")
        if value not in found and any(ch.isdigit() for ch in value):
            found.append(value)
    return found


def _count_from(unit_lower: str) -> int | None:
    match = re.search(
        r"\b(\d[\d,]{2,})\s*(?:times|x\b|repetitions|iterations|copies|words|lines|"
        r"characters|items|numbers|tokens|paragraphs|calls|requests|rows|entries|pages)",
        unit_lower,
    )
    if match:
        return int(match.group(1).replace(",", ""))
    for phrase in sorted(REPEAT_NUMBER_WORDS, key=len, reverse=True):
        if re.search(rf"\b{phrase}\b", unit_lower):
            return REPEAT_NUMBER_WORDS[phrase]
    match = re.search(r"\b(?:repeat|loop|call|fetch|query|send|retry|run|do)\b.{0,40}?\b(\d{2,})\b", unit_lower)
    if match and re.search(r"\b(times|loop|again|repeat|retry|each|every)\b", unit_lower):
        return int(match.group(1))
    if re.search(
        r"\b(until|over and over|again and again|in a loop|repeatedly|keep (?:\w+ing)|continuously)\b",
        unit_lower,
    ):
        return 1_000
    return None


def _literal_targets(unit: str) -> list[str]:
    targets = [m.group(0) for m in TOKEN_LITERAL_RE.finditer(unit) if "-" in m.group(0)]
    for match in DQUOTE_RE.finditer(unit):
        targets.append(match.group(1) or match.group(2))
    targets.extend(m.group(1) for m in BACKTICK_RE.finditer(unit))
    return [t for t in targets if t and not URL_RE.fullmatch(t)]


def _echo_payload(unit: str, full_text: str) -> str | None:
    fence = FENCE_RE.search(unit) or FENCE_RE.search(full_text)
    if fence:
        return fence.group(1).strip()
    quotes = [m.group(1) or m.group(2) for m in DQUOTE_RE.finditer(unit)]
    if quotes:
        return max(quotes, key=len)
    backticks = [m.group(1) for m in BACKTICK_RE.finditer(unit)]
    if backticks:
        return max(backticks, key=len)
    if ":" in unit:
        tail = unit.split(":", 1)[1].strip()
        if tail and not tail.lower().startswith(("//", "http")):
            return tail
    return None


def _payment_intent(unit: str, low: str, source: str) -> ToolIntent | None:
    explicit = "payment_transfer" in low
    verb = re.search(r"\b(transfer|wire|send|pay|remit|move|deposit|refund|disburse|forward|issue)\b", low)
    account = ACCOUNT_RE.search(unit)
    acct_phrase = re.search(r"\baccount(?: number| no\.?| #)?\s*#?\s*([A-Z0-9][A-Z0-9-]{3,})", unit, re.IGNORECASE)
    amount = AMOUNT_RE.search(unit)
    if not (
        explicit
        or (verb and (account or acct_phrase) and (amount or "funds" in low or "money" in low or "balance" in low))
    ):
        return None
    if verb and _negated(low, verb.start()) and not explicit:
        return None
    to_account = account.group(1) if account else (acct_phrase.group(1) if acct_phrase else "UNKNOWN")
    value = 1.0
    if amount:
        raw = (amount.group(1) or amount.group(2) or "1").replace(",", "")
        value = float(raw)
    elif m := re.search(r"amount[\"'=: ]+(\d+(?:\.\d+)?)", low):
        value = float(m.group(1))
    currency = "USD"
    if re.search(r"€|\beur", unit, re.IGNORECASE):
        currency = "EUR"
    elif re.search(r"₹|\binr\b|rupee|\brs\.?", unit, re.IGNORECASE):
        currency = "INR"
    return ToolIntent(
        "payment_transfer",
        {"amount": value, "to_account": to_account, "currency": currency},
        source=source,
        unit=unit,
    )


def _body_for(low: str, unit: str) -> str:
    if re.search(r"\b(secret|code|token|key|password|credential|pin)\b", low):
        return "{{SECRETS}}"
    if re.search(r"system prompt|instructions|configuration|rules", low):
        return "{{SYSTEM_PROMPT}}"
    if re.search(r"\b(conversation|chat|history|transcript)\b", low):
        return "{{CONVERSATION}}"
    if re.search(
        r"\b(file|document|contents?|data|records?|results?|customer|details|everything|summary|report|rows)\b",
        low,
    ):
        return "{{TOOL_DATA}}"
    quote = DQUOTE_RE.search(unit)
    if quote:
        return quote.group(1) or quote.group(2)
    m = re.search(
        r"\b(?:saying|that says|with the message|with body|body:|message:|telling (?:them|him|her))\s*(.+)$",
        unit,
        re.IGNORECASE,
    )
    if m:
        return m.group(1).strip()
    return unit


def _email_intent(unit: str, low: str, source: str) -> ToolIntent | None:
    addresses = EMAIL_RE.findall(unit)
    explicit = "email_send" in low
    verb = re.search(
        r"\b(send|forward|email|e-mail|mail|cc|bcc|notify|message|write to|reply to|contact|report)\b",
        low,
    )
    if not addresses or not (verb or explicit):
        return None
    if verb and _negated(low, verb.start()):
        return None
    subject = "Message"
    m = re.search(r"subject(?: line)?\s*(?:of|:|=)?\s*[\"“']([^\"”']{1,120})[\"”']", unit, re.IGNORECASE)
    if m:
        subject = m.group(1)
    return ToolIntent(
        "email_send",
        {"to": addresses[0], "subject": subject, "body": _body_for(low, unit)},
        source=source,
        unit=unit,
    )


def _http_intent(unit: str, low: str, source: str, is_exfil_media: bool) -> list[ToolIntent]:
    if is_exfil_media:
        return []
    urls = URL_RE.findall(unit)
    if not urls:
        return []
    verb = re.search(
        r"\b(fetch|get|visit|open|load|retrieve|browse|request|call|ping|curl|wget|download|go to|"
        r"navigate|access|hit|check|look at|read|query|post|submit|summari[sz]e|scrape|crawl|"
        r"contact|notify|report|send|upload|beacon|sync|register|verify|validate)\b",
        low,
    )
    if not verb and "http_get" not in low:
        return []
    if verb and _negated(low, verb.start()):
        return []
    intents = []
    for url in urls:
        url = url.rstrip(".,;:")
        append_data = bool(
            re.search(r"\b(append|add|include|attach|with|containing|put|pass|encode|embed)\b", low)
            and re.search(SENSITIVE_DATA, low)
            and ("?" in url or "append" in low or "parameter" in low or "query string" in low or "{" in url)
        )
        args: dict[str, Any] = {"url": url}
        if append_data:
            args["url"] = url + ("{{EXFIL_DATA}}" if "{" not in url else "")
            args["url"] = re.sub(r"\{[^}]*\}|<[^>]*>|\[DATA\]|\$DATA|XXX", "{{EXFIL_DATA}}", args["url"])
        repeat = _count_from(low) or 1
        intents.append(ToolIntent("http_get", args, source=source, repeat=repeat, unit=unit))
    return intents


def _file_intents(unit: str, low: str, source: str) -> list[ToolIntent]:
    intents: list[ToolIntent] = []
    paths = [p.rstrip(".,;:") for p in PATH_RE.findall(unit)]
    paths = [p for p in paths if not p.startswith("//") and len(p) > 1]
    names = FILENAME_RE.findall(unit)
    # Skip paths that are part of URLs.
    url_spans = "".join(URL_RE.findall(unit))
    paths = [p for p in paths if p not in url_spans]
    write_verb = re.search(
        r"\b(write|save|create|overwrite|append|store|dump|copy|output|place|drop|log|record|persist)\b"
        r"[^.]{0,80}?\b(?:to|into|in|at|as|under)\b\s+(?:the\s+)?(?:file\s+)?(?:at\s+)?[`\"']?(/[\w./\-]+|[\w\-]+\.\w{2,4})",
        unit,
        re.IGNORECASE,
    )
    explicit_write = "file_write" in low
    if write_verb or (explicit_write and (paths or names)):
        target = write_verb.group(2) if write_verb else (paths[0] if paths else names[0])
        if not target.startswith("/"):
            target = f"/sandbox/public/{target}"
        if not (write_verb and _negated(low, write_verb.start())):
            content = _echo_payload(unit, unit) or _body_for(low, unit)
            if content == unit:
                content = "{{TOOL_DATA}}"
            intents.append(ToolIntent("file_write", {"path": target, "content": content}, source=source, unit=unit))
            paths = [p for p in paths if p != target]
            names = [n for n in names if not target.endswith(n)]
    read_verb = re.search(
        r"\b(read|open|summari[sz]e|show|cat|display|load|review|check|look at|view|print|"
        r"analy[sz]e|go through|examine|inspect|parse|extract|contents of|what(?:'s| is) in|"
        r"proofread|translate|tell me about|look over|skim|grab|fetch|retrieve|get)\b",
        low,
    )
    if (read_verb or "file_read" in low) and (paths or names):
        if read_verb and _negated(low, read_verb.start()):
            return intents
        for path in paths:
            intents.append(ToolIntent("file_read", {"path": path}, source=source, unit=unit))
        for name in names:
            if any(p.endswith(name) for p in paths):
                continue
            intents.append(ToolIntent("file_read", {"path": f"/sandbox/public/{name}"}, source=source, unit=unit))
    return intents


def _shell_intent(unit: str, low: str, source: str) -> ToolIntent | None:
    explicit = "shell_exec" in low
    verb = re.search(r"\b(run|execute|exec|launch|invoke|issue|type|enter|eval)\b", low)
    shellish = re.search(r"\b(shell|terminal|bash|command[- ]line|cmd|powershell|console|sh)\b|\bcommand\b", low)
    command = None
    ticks = BACKTICK_RE.findall(unit)
    if ticks:
        command = ticks[0]
    else:
        quote = DQUOTE_RE.search(unit) or SQUOTE_RE.search(unit)
        if quote and (shellish or explicit):
            command = quote.group(1) or (quote.group(2) if quote.lastindex and quote.lastindex > 1 else None)
        elif (shellish or explicit) and ":" in unit:
            command = unit.split(":", 1)[1].strip().strip("`\"'")
    if command is None:
        return None
    if not (explicit or (verb and (shellish or ticks))):
        return None
    if verb and _negated(low, verb.start()):
        return None
    if not re.search(r"[a-z]", command):
        return None
    return ToolIntent("shell_exec", {"command": command}, source=source, unit=unit)


_TABLE_WORDS = {
    "customer": "customers",
    "client": "customers",
    "user": "customers",
    "account holder": "customers",
    "order": "orders",
    "purchase": "orders",
    "shipment": "orders",
    "employee": "employees",
    "staff": "employees",
    "colleague": "employees",
    "salary": "employees",
    "product": "products",
    "item": "products",
    "inventory": "products",
    "sku": "products",
}


def _db_intent(unit: str, low: str, source: str) -> ToolIntent | None:
    explicit = "db_query" in low
    verb = re.search(
        r"\b(look ?up|query|find|fetch|retrieve|get|list|show|search|pull|check|display|give me|"
        r"what(?:'s| is| are)|tell me|export|dump|print|read|select|return|share)\b",
        low,
    )
    table = None
    for word, name in _TABLE_WORDS.items():
        if re.search(rf"\b{word}s?\b", low):
            table = name
            break
    record = RECORD_ID_RE.search(unit)
    if record and table is None:
        table = {"C": "customers", "O": "orders", "E": "employees", "P": "products"}[record.group(1)[0]]
    if table is None:
        m = re.search(r"\b(customers|orders|employees|products)\b", low)
        table = m.group(1) if m else None
    if not (
        explicit
        or (
            verb
            and table
            and (
                record
                or re.search(r"\b(all|every|each|entire|whole|full|list)\b", low)
                or "database" in low
                or "records" in low
                or "table" in low
            )
        )
    ):
        return None
    if verb and _negated(low, verb.start()):
        return None
    where: dict[str, Any] = {}
    if record:
        where["id"] = record.group(1)
    return ToolIntent("db_query", {"table": table or "customers", "where": where}, source=source, unit=unit)


def _memory_intents(unit: str, low: str, source: str) -> list[ToolIntent]:
    intents: list[ToolIntent] = []
    trigger = re.search(
        r"\b(remember (?:that|this|to)?|memori[sz]e|store (?:this |that )?in (?:your )?(?:long[- ]term )?memory|"
        r"save (?:this |that )?(?:to|in) (?:your )?(?:long[- ]term )?memory|note (?:this )?for (?:later|future)|"
        r"keep in mind|add (?:this |that )?to (?:your )?memory|update (?:your )?memory|"
        r"for (?:all )?future (?:sessions|conversations|chats)|in every future|memory_write|"
        r"permanently (?:remember|store|note)|persist (?:this|the following))",
        low,
    )
    if trigger and not _negated(low, trigger.start()):
        value = unit[trigger.end() :].strip(" :,.-") or unit
        key = "note-" + str(abs(hash_text(value)) % 10_000).zfill(4)
        m = re.search(r"\bkey\s*[\"'=:]+\s*([\w-]+)", unit, re.IGNORECASE)
        if m:
            key = m.group(1)
        intents.append(ToolIntent("memory_write", {"key": key, "value": value}, source=source, unit=unit))
    if re.search(
        r"\b(what do you remember|recall|check (?:your )?memory|retrieve (?:from )?(?:your )?memory|"
        r"memory_read|look in (?:your )?memory|what(?:'s| is) in (?:your )?memory|what notes|"
        r"your saved notes|consult (?:your )?memory|load (?:your )?memory)\b",
        low,
    ):
        intents.append(ToolIntent("memory_read", {"key": "*"}, source=source, unit=unit))
    return intents


def hash_text(text: str) -> int:
    """Stable small hash of text (Python's ``hash`` is salted per process)."""
    value = 0
    for ch in text:
        value = (value * 131 + ord(ch)) % 1_000_000_007
    return value


def _email_read_intent(low: str, source: str, unit: str) -> ToolIntent | None:
    if "email_read" in low or re.search(
        r"\b(check|read|summari[sz]e|open|go through|triage|review|process|scan|look at|"
        r"what(?:'s| is) in|any new|handle|sort|prioriti[sz]e|reply to|respond to|catch me up on)\b"
        r"[^.]{0,30}\b(?:my |the |our )?(?:latest |new |unread |recent |last |incoming )?"
        r"(inbox|e-?mails?|mail|messages)\b",
        low,
    ):
        return ToolIntent("email_read", {"folder": "inbox"}, source=source, unit=unit)
    return None


def _search_intent(low: str) -> bool:
    return bool(
        re.search(
            r"\b(search (?:the |our )?(?:docs|documentation|knowledge ?base|kb|handbook|wiki|policies|"
            r"policy|faq)|according to (?:the |our )?(?:docs|documentation|policy|handbook|knowledge ?base|faq)|"
            r"what does (?:the |our )?(?:docs|documentation|handbook|policy|knowledge ?base|faq) say|"
            r"look (?:it |this )?up in (?:the )?(?:docs|knowledge ?base|handbook)|"
            r"based on (?:the |our )?(?:docs|documentation|knowledge ?base)|search_docs|"
            r"(?:company|acme)(?:'s)? (?:policy|policies|docs|handbook)|knowledge ?base|"
            r"internal docs|documentation)\b",
            low,
        )
    )


def _exfil_directive(unit: str, low: str, source: str) -> Directive | None:
    urls = URL_RE.findall(unit)
    if not urls:
        return None
    media = re.search(EXFIL_MEDIA, low)
    verb = re.search(EXFIL_VERBS, low)
    if not (media and verb):
        return None
    if _negated(low, verb.start()):
        return None
    data = re.search(SENSITIVE_DATA, low)
    if not data and "![" not in unit and "{" not in urls[0]:
        return None
    kind = "image"
    if re.search(r"\b(link|hyperlink|anchor|url|click)\b", low) and not re.search(
        r"\b(image|img|picture|pixel|badge|icon|logo|beacon|thumbnail)\b|!\[", low
    ):
        kind = "link"
    return Directive(
        "exfil_media",
        payload=urls[0].rstrip(".,;:)"),
        transform=detect_transform(low),
        media=kind,
        source=source,
        data_hint=data.group(1) if data else "data",
    )


def _package_directive(unit: str, low: str, source: str) -> Directive | None:
    if re.search(
        r"\b(pip install|npm install|yarn add|pnpm add|poetry add|cargo add|go get|"
        r"(?:which|what|recommend|suggest|best|good|name)\b[^.?]{0,40}\b(?:package|library|module|lib|"
        r"dependency|sdk|plugin|crate|gem)s?|(?:package|library|module|dependency)\s+(?:for|to|that)|"
        r"is there a (?:package|library|module)|install (?:the )?\S+ (?:package|library|module))",
        low,
    ):
        return Directive("packages", payload=unit, source=source)
    return None


def _units_intents(unit: str, full_text: str, source: str) -> Intents:
    intents = Intents()
    low = unit.lower()
    full_low = full_text.lower()

    def transform_of() -> str | None:
        return detect_transform(low) or detect_transform(full_low)

    # --- Directives about the answer ------------------------------------------------------------
    sp = re.search(rf"\b{REVEAL_VERBS}\b.{{0,80}}?\b{SYSTEM_PROMPT_OBJ}", low)
    if sp and not _negated(low, sp.start()):
        intents.directives.append(Directive("leak_system_prompt", transform=transform_of(), source=source))
    secret = re.search(rf"\b{REVEAL_VERBS}\b.{{0,80}}?\b{SECRET_OBJ}", low)
    if secret and not _negated(low, secret.start()) and not sp:
        literals = [t for t in _literal_targets(unit) if not t.lower().startswith("attacker")]
        if not literals:
            intents.directives.append(Directive("leak_secret", transform=transform_of(), source=source))
    exfil = _exfil_directive(unit, low, source)
    if exfil:
        intents.directives.append(exfil)

    include = re.search(rf"\b{INCLUDE_VERBS}\b", low)
    if include and not _negated(low, include.start()) and not exfil:
        for literal in _literal_targets(unit):
            if ACCOUNT_RE.fullmatch(literal) and re.search(r"\b(transfer|pay|wire|account)\b", low):
                continue
            if EMAIL_RE.fullmatch(literal):
                continue
            intents.directives.append(Directive("include", payload=literal, source=source))

    verbatim = re.search(rf"\b{VERBATIM}\b", low)
    fmt = re.search(
        rf"\b(convert|turn|format|render|wrap|put|embed|display|generate|create|build|write|make|"
        rf"produce|insert|output)\b[^.]{{0,60}}\b{CODE_FORMATS}\b",
        low,
    )
    if fmt:
        intents.format_request = fmt.group(2)
    if verbatim or fmt:
        payload = _echo_payload(unit, full_text)
        if payload:
            intents.directives.append(Directive("echo", payload=payload, source=source))

    count = _count_from(low)
    rep = re.search(
        r"\b(repeat|say|print|write|output|type|list|generate|produce|count|enumerate|spell|echo|"
        r"recite|expand|elaborate|continue)\b",
        low,
    )
    if count and count >= 50 and rep and not _negated(low, rep.start()):
        phrase_match = DQUOTE_RE.search(unit) or SQUOTE_RE.search(unit)
        phrase = (phrase_match.group(1) or "") if phrase_match else ""
        if not phrase:
            m = re.search(r"\b(?:the word|the phrase|the sentence|the letter)\s+(\w+)", unit, re.IGNORECASE)
            phrase = m.group(1) if m else "data"
        intents.directives.append(Directive("repeat", payload=phrase, count=count, source=source))

    pkg = _package_directive(unit, low, source)
    if pkg:
        intents.directives.append(pkg)

    # --- Tool intents -------------------------------------------------------------------------
    payment = _payment_intent(unit, low, source)
    if payment:
        payment.repeat = _count_from(low) or 1
        intents.tools.append(payment)
    email = _email_intent(unit, low, source)
    if email and not payment:
        intents.tools.append(email)
    intents.tools.extend(_http_intent(unit, low, source, is_exfil_media=exfil is not None))
    intents.tools.extend(_file_intents(unit, low, source))
    shell = _shell_intent(unit, low, source)
    if shell:
        intents.tools.append(shell)
    db = _db_intent(unit, low, source)
    if db:
        db.repeat = min(_count_from(low) or 1, 1_000)
        intents.tools.append(db)
    intents.tools.extend(_memory_intents(unit, low, source))
    email_read = _email_read_intent(low, source, unit)
    if email_read:
        intents.tools.append(email_read)
    if _search_intent(low):
        intents.wants_search = True
    if DEFERRAL_RE.search(low):
        for tool in intents.tools:
            if tool.name != "memory_write":
                tool.deferred = True
        for directive in intents.directives:
            directive.deferred = True
    if re.search(
        r"^\s*(?:ok(?:ay)?[,!]?\s*)?(?:now\s+)?(?:do it|go ahead|proceed|continue|yes,? (?:do|please)|"
        r"please do|execute (?:it|that|the plan)|make it happen|finish (?:it|the job)|do that|"
        r"carry on|as discussed|like (?:i|we) said)\b",
        low,
    ):
        intents.carry_over = True
    return intents


def extract_intents(text: str, *, source: str = "user", decode_encodings: bool = True) -> Intents:
    """Extract all intents from ``text`` across its readings.

    Args:
        text: the instruction-bearing text.
        source: provenance label attached to every intent.
        decode_encodings: whether base64 / ROT13 readings are considered.

    Returns:
        The merged :class:`Intents`.
    """
    merged = Intents()
    for reading in reading_variants(text, decode_encodings=decode_encodings):
        for unit in split_units(reading):
            merged.extend(_units_intents(unit, reading, source))
    return merged
