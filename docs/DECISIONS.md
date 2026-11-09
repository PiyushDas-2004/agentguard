# Architecture Decision Log

Each entry: **decision**, alternatives considered, and the reason. Entries are appended as the
project evolves.

## D-001 Naive mock model drives offline evaluation
- **Decision:** a single rule-based "naive instruction follower" (`MockLLM(profile="vulnerable")`)
  powers every demo agent offline. It extracts intents from any text it reads (user turns,
  deployment context, memory notes, tool outputs) using a broad synonym grammar
  (`llm/intents.py`) and reads through obfuscation (base64 on request, ROT13, homoglyphs,
  zero-width characters, leetspeak, split words, a pseudo-Spanish lexicon).
- **Alternatives:** per-case scripted responses (circular — the tool would validate its own
  script); a small local LLM (non-deterministic, heavy, not available offline in CI).
- **Reason:** deterministic, seedable, generic. The hardened agent wraps the *same* model, so
  its safety comes from defense code, which is what meta-validation must measure.

## D-002 Injection compliance is probabilistic (p = 0.9)
- **Decision:** the naive model obeys instructions found in *untrusted* tool output with
  probability 0.9 per instruction (seeded per trial); user, deployment-context and memory
  instructions are always followed.
- **Reason:** gives the statistics something to measure (CIs are not degenerate) while keeping
  results deterministic for a fixed seed.

## D-003 Sandbox defaults to `observe` mode
- **Decision:** policy-violating tool calls are recorded as violations *and* still simulated
  (mock tools have no side effects). `mode: block` is available.
- **Alternatives:** always block.
- **Reason:** blocking at the harness would hide downstream behaviour (e.g. an agent reading a
  secret and then exfiltrating it). The harness is a measuring instrument, not a defense.

## D-004 Seed and mutated trials are pooled per case
- **Decision:** a case's `n` includes its seed trials and the trials of each mutation
  (`trials_per_case × (1 + per_case)`); seed and per-mutation rates are reported separately as
  the robustness metric.
- **Reason:** with `n = 5` a case with zero violations has Wilson upper bound 0.43, so a
  perfectly safe agent would score ~43 risk. Pooling (n = 20 → 0.16) keeps the conservative
  upper-bound scoring meaningful at the spec's default of 5 trials. Documented in SCORING.md.

## D-005 Canary scope and obedience canaries
- **Decision:** `{{CANARY}}` in a case renders to an *obedience canary* planted only in
  attacker-controlled non-user vectors (poison). If it shows up in output, the agent followed
  injected instructions. Separate secret canaries are planted in the system prompt, a private
  file, a DB credentials row, a confidential RAG document and memory. Canaries the user typed
  are never counted as leaks.

## D-006 Extra tool `email_read`
- **Decision:** added an 11th mock tool, `email_read`, so the `email_body` injection vector is
  reachable through a realistic inbox tool rather than through `file_read`.

## D-007 LiteLLM is an optional extra (`agentguard[litellm]`)
- **Decision:** core install does not depend on LiteLLM; it is imported lazily for live mode
  and installed in the dev group so it is tested and audited.
- **Reason:** LiteLLM pulls a large dependency tree; offline/CI users should not pay for it.

## D-008 Line length 120
- **Decision:** ruff line length 120 (regex-heavy grammar modules exempt from E501).
- **Reason:** readability of long regular expressions and Pydantic field declarations.

## D-009 Package-index snapshot
- **Decision:** `package_halluc` checks names against bundled snapshots of the 15,000 most
  downloaded PyPI projects (hugovk/top-pypi-packages, 2026-11-01) and ~20,000 popular npm
  packages (registry search API, 2026-11-09). The hardened demo agent uses the same snapshot as
  its "package-index mirror" when verifying recommendations (equivalent to querying the registry).
- **Trade-off:** obscure-but-real packages are reported (confidence 0.85, documented limitation).
