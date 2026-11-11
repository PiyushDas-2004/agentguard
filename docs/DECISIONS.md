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

## D-010 Meta-validation decision rule
- **Decision:** AgentGuard "predicts vulnerable" for an (agent, category) pair when at least one
  case in that category has status `fail` (Wilson lower bound > 0.10).
- **Alternatives:** majority of cases failing; mean violation rate above a threshold.
- **Reason:** mirrors how a security team reads a report (one confirmed failing case is a
  finding) and uses the same statistical status users see; inconclusive cases never count as
  findings, which keeps the false-positive rate honest.

## D-011 Datasets authored with a validation loop
- **Decision:** every seed case was run against the vulnerable, partially hardened and hardened
  agents while authoring (`scripts/probe_cases.py`). Cases the naive model did not understand were
  rephrased to clearer attacker language; cases that tripped the hardened agent were kept and the
  hardened agent's *defense code* was improved instead (never the case or the ground truth).
- **Reason:** keeps the dataset honest (no attacks softened to flatter the hardened agent) while
  ensuring offline runs exercise the intended technique.

## D-012 Mock tool results avoid instruction-like phrasing
- **Decision:** mock tool results are phrased as data ("Payment TX-00001 queued (simulated):
  …, beneficiary …") so the naive model does not re-read its own tool results as new requests.
- **Reason:** the previous phrasing caused cascading self-triggered transfers in the simulator,
  which is an artefact of the mock rather than agent behaviour worth measuring.

## D-013 Path normalization in argument constraints
- **Decision:** path-like arguments are normalized (`posixpath.normpath`) before regex
  constraints are evaluated, and a mismatch after normalization is reported as path traversal.
- **Reason:** `/sandbox/public/../private/x` satisfied `^/sandbox/public/` (found while
  authoring EXCESSIVE_AGENCY cases).

## D-014 Optional CA bundle build secret in the Dockerfile
- **Decision:** `docker build --secret id=ca_bundle,src=ca.crt` lets `uv` trust a corporate /
  TLS-intercepting proxy CA without baking it into the image.
- **Reason:** the build sandbox used to develop AgentGuard intercepts TLS; the secret is optional
  and unused elsewhere.

## D-015 Report embeds a bounded number of trials per case
- **Decision:** `reports.embed_trials_per_case` (default 3: violations first) transcripts are
  embedded per case; all transcripts remain in the JSONL store and dashboard.
- **Reason:** a full demo run has ~8,000 trials; embedding all would produce a >50 MB HTML file.

## D-016 Category purity of detectors (found by meta-validation)
- **Finding:** the first full meta-validation flagged the RAG agent (no action tools) as
  vulnerable to EXCESSIVE_AGENCY. Inspection showed a *correct* detection — the agent leaked its
  system-prompt canary when asked for "the database password" — attributed to the wrong category
  because EXA-029 listed the `canary` detector.
- **Decision:** EXCESSIVE_AGENCY cases use agency detectors only (`tool_policy`, optionally
  `exfil`/`resource`); disclosure detectors (`canary`, `system_prompt`, `pii`) belong to
  disclosure categories. Enforced by `lint-datasets`. Ground truth and detectors were not changed.

## D-017 Hosted web app: verified targets, BYOK Gemini, secrets in memory only
- **Decision:** the hosted service (`agentguard serve`) scans only endpoints whose owner proved
  control (well-known file or DNS TXT); all outbound traffic goes through an SSRF-safe transport
  that validates resolved addresses at connect time; users bring their own Gemini key, which is
  held in memory for one scan and never persisted; only `http` and `openai_compat` targets are
  offered (the `python`/`langchain`/`mcp` targets would execute code on the server).
- **Reason:** a public service that sends attack traffic to user-supplied URLs is otherwise an
  attack proxy and an SSRF primitive; storing third-party API keys would make the database a
  high-value target. Deterministic detectors keep the service useful without any key.
- **Trade-off:** single instance (in-memory queue/limiter); a restart fails running scans.

## D-018 `${VAR}` interpolation is a CLI-only feature
- **Decision:** `HTTPTarget(interpolate_headers=False)` for hosted targets.
- **Reason:** found during the hosted-app design: a user-controlled URL such as
  `https://x/?k=${AGENTGUARD_SECRET_KEY}` would otherwise send server secrets to the target.
