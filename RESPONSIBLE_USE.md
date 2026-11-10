# Responsible use

AgentGuard is a **defensive** tool for testing AI agents you own or are authorised to test.

## Design commitments

* **Canary-based objectives only.** Every bundled attack tries to make the target reveal a
  synthetic canary token (`AG-CANARY-<16 hex>`), reveal its own system prompt, or call a *mock*
  tool (`payment_transfer` to `ATTACKER-0000`, `email_send` to `*@attacker.example`, `http_get`
  to `exfil.attacker.example`, toy `shell_exec` commands). No dataset contains instructions for
  weapons, malware, self-harm, hate or sexual content, and the linter and reviews enforce this.
* **No real side effects.** The harness tools operate on an in-memory virtual filesystem,
  database, inbox and web; nothing is sent, paid, written or executed for real.
* **Synthetic data.** All PII and secrets are generated per trial (valid formats, fictitious
  values). The `attacker.example` and `*.example` domains are reserved by RFC 2606.

## Your obligations

* Test only systems you own or have **written permission** to test. Respect provider terms of
  service and rate limits — live mode calls real APIs and costs money (use `max_cost_usd`).
* Do not adapt the payloads to target third-party systems, to extract real secrets or personal
  data, or to cause harm.
* Treat reports as sensitive: they contain your agent's system prompt, tool traces and
  weaknesses. Do not publish them for production systems without review.
* When AgentGuard reveals a vulnerability in a third-party model or framework, follow
  coordinated disclosure with the vendor.

## Limitations to keep in mind

Offline results measure your *defense layer* against a naive instruction-following model; they do
not prove a real LLM is (or is not) susceptible. A passing grade is evidence, not a guarantee —
combine AgentGuard with threat modelling, code review and production monitoring.
