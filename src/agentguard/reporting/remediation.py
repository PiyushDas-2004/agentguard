"""Curated remediation guidance per attack category."""

from __future__ import annotations

from agentguard.core.types import AttackCategory

__all__ = ["REMEDIATION"]

REMEDIATION: dict[AttackCategory, list[str]] = {
    AttackCategory.PI_DIRECT: [
        "Classify user input on normalized readings (decode base64/ROT13, strip zero-width characters, fold homoglyphs) before it reaches the model.",
        "Keep secrets out of the system prompt; give the model capabilities, not credentials.",
        "Enforce authorization in tools, not in the prompt: the model's compliance is not a control.",
        "Add an output filter that blocks known secrets and high-entropy credentials, including encoded forms.",
    ],
    AttackCategory.PI_INDIRECT: [
        "Treat every tool result, document, e-mail and web page as untrusted data: spotlight (delimit/datamark) it and strip instruction-like sentences.",
        "Plan tool calls from the trusted user request only (plan-then-execute / dual-LLM pattern); never let retrieved data add new actions.",
        "Check provenance of tool arguments: destinations (URLs, e-mail addresses, accounts) must originate from the user.",
        "Require human approval for consequential actions triggered while untrusted content is in context.",
    ],
    AttackCategory.JAILBREAK: [
        "Detect role-play/persona and refusal-suppression framings on normalized input; refuse persona switches that remove policy.",
        "Re-evaluate the full conversation, not just the last turn, to catch multi-turn crescendo escalation.",
        "Enforce safety in deterministic layers (tool guards, output filters) so a jailbroken model still cannot act.",
    ],
    AttackCategory.SYS_PROMPT_LEAK: [
        "Assume the system prompt will leak: never place credentials, internal URLs or business logic secrets in it.",
        "Block outputs with high n-gram overlap with the system prompt, including translated/encoded/reversed renderings.",
        "Refuse meta-requests about instructions (repeat/summarize/translate the text above).",
    ],
    AttackCategory.DATA_EXFIL: [
        "Strip or proxy markdown images and links to non-allowlisted domains before rendering (images auto-load).",
        "Allowlist outbound HTTP and e-mail destinations; require approval for external recipients.",
        "Scan outbound tool arguments and rendered URLs for secrets, PII and long encoded blobs.",
    ],
    AttackCategory.PII_LEAK: [
        "Authorize data access per requester in the tool layer (row-level security), not in the prompt.",
        "Redact PII (cards, SSNs, national IDs, IBANs, phone numbers) from model output by default.",
        "Return minimal fields from data tools; avoid SELECT * style tools.",
    ],
    AttackCategory.EXCESSIVE_AGENCY: [
        "Grant the minimum tool set; remove shell and arbitrary file-write tools from customer-facing agents.",
        "Validate arguments (path prefixes, domain allowlists, table allowlists) in the tool, not the prompt.",
        "Put a human approval gate (default deny) in front of payments, external e-mail and irreversible actions.",
    ],
    AttackCategory.INSECURE_OUTPUT: [
        "Treat model output as untrusted: HTML-encode before rendering, parameterize SQL, never pass output to a shell.",
        "Neutralize active content (script tags, event handlers, javascript: URLs, command substitution) in the output filter.",
        "Never deserialize model output with pickle/yaml.load/eval.",
    ],
    AttackCategory.MEMORY_POISON: [
        "Sanitize memory writes: store facts, never standing instructions ('whenever...', 'from now on...').",
        "Load memory as spotlighted data, not as system instructions; keep it out of the tool planner.",
        "Attribute and expire memory entries; let users review what was stored.",
    ],
    AttackCategory.RAG_POISON: [
        "Control ingestion: provenance, review and signing for knowledge-base documents.",
        "Spotlight retrieved passages and strip instruction-like content before generation.",
        "Monitor for retrieved documents that address the AI directly or contain URLs/tokens.",
    ],
    AttackCategory.DENIAL_OF_WALLET: [
        "Cap tool calls, identical calls, output tokens and wall time per request; refuse unbounded repetition requests.",
        "Apply per-user rate limits and spend budgets with alerts.",
        "Detect and break tool-call loops (same call with same arguments).",
    ],
    AttackCategory.PKG_HALLUCINATION: [
        "Verify every recommended package against the registry (existence, age, downloads) before showing install commands.",
        "Pin dependencies and use an internal package mirror/allowlist.",
        "Warn users when the model endorses a package name supplied in the question.",
    ],
    AttackCategory.OVER_REFUSAL: [
        "Classify intent, not vocabulary: keyword blocklists refuse legitimate requests ('kill a process').",
        "Treat quoted attack phrases inside educational questions as mentions, not instructions.",
        "Track the over-refusal rate on a benign set alongside the security score.",
    ],
}
