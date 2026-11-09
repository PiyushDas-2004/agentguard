"""Attack-category metadata, MITRE ATLAS catalogue and dataset minimums."""

from __future__ import annotations

from dataclasses import dataclass

from agentguard.core.types import AttackCategory

__all__ = ["ATLAS_TECHNIQUES", "CATEGORY_INFO", "MIN_CASES", "CategoryInfo"]

# MITRE ATLAS techniques relevant to LLM agents (https://atlas.mitre.org/techniques).
ATLAS_TECHNIQUES: dict[str, str] = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0024": "Exfiltration via AI Inference API",
    "AML.T0025": "Exfiltration via Cyber Means",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0029": "Denial of AI Service",
    "AML.T0034": "Cost Harvesting",
    "AML.T0070": "RAG Poisoning",
    "AML.T0071": "False RAG Entry Injection",
    "AML.T0080": "AI Agent Context Poisoning",
    "AML.T0080.000": "AI Agent Context Poisoning: Memory",
    "AML.T0080.001": "AI Agent Context Poisoning: Thread",
    "AML.T0062": "Discover LLM Hallucinations",
    "AML.T0060": "Publish Hallucinated Entities",
    "AML.T0068": "LLM Prompt Obfuscation",
    "AML.T0065": "LLM Prompt Crafting",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0011": "User Execution",
    "AML.T0067": "LLM Trusted Output Components Manipulation",
    "AML.T0077": "LLM Response Rendering",
    "AML.T0069": "Discover LLM System Information",
    "AML.T0048": "External Harms",
    "AML.T0061": "LLM Prompt Self-Replication",
}


@dataclass(frozen=True)
class CategoryInfo:
    """Human-readable metadata for an attack category."""

    title: str
    summary: str
    prefix: str


CATEGORY_INFO: dict[AttackCategory, CategoryInfo] = {
    AttackCategory.PI_DIRECT: CategoryInfo(
        "Direct prompt injection", "The user tries to override the agent's instructions.", "PI-DIR"
    ),
    AttackCategory.PI_INDIRECT: CategoryInfo(
        "Indirect prompt injection",
        "Instructions hidden in data the agent reads (documents, web pages, e-mail, tool output, memory).",
        "PI-IND",
    ),
    AttackCategory.JAILBREAK: CategoryInfo(
        "Jailbreak", "Role-play, hypotheticals and multi-turn escalation that talk the agent out of its policy.", "JB"
    ),
    AttackCategory.SYS_PROMPT_LEAK: CategoryInfo(
        "System prompt leakage", "Extraction of the agent's confidential instructions.", "SPL"
    ),
    AttackCategory.DATA_EXFIL: CategoryInfo(
        "Data exfiltration", "Secrets or PII smuggled out through URLs, images, e-mail or HTTP requests.", "EXF"
    ),
    AttackCategory.PII_LEAK: CategoryInfo(
        "PII disclosure", "Personal data of other users disclosed to an unauthorized requester.", "PII"
    ),
    AttackCategory.EXCESSIVE_AGENCY: CategoryInfo(
        "Excessive agency",
        "Unauthorized or unapproved tool actions (payments, shell, writes, privilege escalation).",
        "EXA",
    ),
    AttackCategory.INSECURE_OUTPUT: CategoryInfo(
        "Insecure output handling",
        "Active content (XSS, SQLi, shell injection, unsafe deserialization) emitted downstream.",
        "IOH",
    ),
    AttackCategory.MEMORY_POISON: CategoryInfo(
        "Memory poisoning", "Malicious instructions persisted to long-term memory and obeyed in later sessions.", "MEM"
    ),
    AttackCategory.RAG_POISON: CategoryInfo(
        "RAG poisoning", "Poisoned knowledge-base documents that hijack answers or trigger actions.", "RAGP"
    ),
    AttackCategory.DENIAL_OF_WALLET: CategoryInfo(
        "Denial of wallet", "Inputs that cause runaway loops, giant outputs or excessive tool use.", "DOW"
    ),
    AttackCategory.PKG_HALLUCINATION: CategoryInfo(
        "Package hallucination", "Recommending packages that do not exist (slopsquatting).", "PKG"
    ),
    AttackCategory.OVER_REFUSAL: CategoryInfo(
        "Over-refusal", "Legitimate requests that the agent wrongly refuses.", "BEN"
    ),
}

MIN_CASES: dict[AttackCategory, int] = {
    AttackCategory.PI_DIRECT: 40,
    AttackCategory.PI_INDIRECT: 40,
    AttackCategory.JAILBREAK: 30,
    AttackCategory.SYS_PROMPT_LEAK: 20,
    AttackCategory.DATA_EXFIL: 25,
    AttackCategory.PII_LEAK: 15,
    AttackCategory.EXCESSIVE_AGENCY: 30,
    AttackCategory.INSECURE_OUTPUT: 20,
    AttackCategory.MEMORY_POISON: 10,
    AttackCategory.RAG_POISON: 15,
    AttackCategory.DENIAL_OF_WALLET: 10,
    AttackCategory.PKG_HALLUCINATION: 10,
    AttackCategory.OVER_REFUSAL: 50,
}
