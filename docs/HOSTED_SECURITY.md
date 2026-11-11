# Hosted service: security design

`agentguard serve` runs AgentGuard as a multi-user web application: people sign up, register
their agent's endpoint, prove they own it, run scans and read reports. Because the service sends
attack traffic to URLs supplied by its users, it is designed first as a **safe outbound HTTP
client** and second as a web app. This document lists each threat and the control that addresses
it, with the test that checks it.

## Threats and controls

| # | Threat | Control | Tested in |
|---|---|---|---|
| 1 | **Using AgentGuard to attack someone else's system** | A target can be scanned only after its owner serves a per-target token at `/.well-known/agentguard.txt` or in DNS TXT `_agentguard.<host>`. Ownership is per origin and per user. Scans are capped (cases, trials, requests/second, scans/day, one active scan per user). | `test_unverified_targets_cannot_be_scanned_and_wrong_token_fails`, `test_users_cannot_access_each_others_data` |
| 2 | **SSRF** to the cloud metadata service, the database or other internal hosts | `netsafe.check_url` (https only, no credentials, no private/loopback/link-local literals, no `localhost`/`.local`/`.internal`), and `GuardedNetworkBackend`, which resolves every hostname itself and refuses to connect if **any** resolved address is non-public (blocks DNS rebinding, decimal/hex/short IPv4 forms, IPv4-mapped/6to4/Teredo IPv6). Redirects are never followed, env proxies are ignored (`trust_env=False`), unix sockets are refused, response bodies are capped at 2 MiB, and each scan is pinned to the verified origin. | `tests/unit/test_netsafe.py`, `test_production_policy_rejects_private_and_http_targets` |
| 3 | **Leaking the user's Gemini key or agent credential** | Both are held only in memory for the duration of one scan (`ScanManager._secrets`), never written to the database, logs or reports, removed when the scan ends, and redacted from any error text. The Gemini key goes in the `x-goog-api-key` header (never a URL). `SecretStr` config fields are excluded from serialization and `repr`. A restart fails in-flight scans rather than persisting secrets. | `test_scan_end_to_end_with_secret_handling`, `tests/unit/llm/test_gemini_client.py` |
| 4 | **Leaking server secrets** through user-controlled URLs/headers (`${AGENTGUARD_SECRET_KEY}`) | The CLI's `${VAR}` expansion is disabled for hosted targets (`HTTPTarget(interpolate_headers=False)`). | `test_scan_end_to_end_with_secret_handling` |
| 5 | **Server-side template injection** via the custom request body | Templates may contain only `{{ var }}` substitutions of `message`, `messages`, `system_prompt`, `session`, `case_id` with optional slicing and the `tojson/lower/upper/trim` filters; no statements, attribute access, calls or arithmetic. Rendering additionally uses Jinja's `SandboxedEnvironment`. | `test_dangerous_or_useless_templates_are_rejected` |
| 6 | **XSS** from agent output (which is attacker-influenced by design) | All templates autoescape. Reports are served with `Content-Security-Policy: sandbox allow-scripts …`, i.e. in an opaque origin without access to the app's cookies or same-origin requests. Every page has a nonce-based CSP (`default-src 'none'`, no `unsafe-eval`, no inline scripts without the nonce), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP. | `test_health_and_security_headers`, `test_scan_end_to_end_with_secret_handling` |
| 7 | **CSRF** | Every state-changing request needs a per-session CSRF token (anonymous double-submit cookie before sign-in) and is rejected if `Origin`/`Referer` is a different origin. Session cookies are `SameSite=Lax`, `HttpOnly`, `Secure`, `__Host-` prefixed in production. | `test_state_changes_require_csrf_and_same_origin` |
| 8 | **Account takeover / credential stuffing** | argon2id hashes; minimum 12-character passwords with common/self-referential checks; generic error messages and constant-time dummy verification for unknown e-mails; per-IP and per-e-mail rate limits; 15-minute lockout after 10 failures; invite-code sign-up by default. Sessions are random 256-bit tokens stored only as SHA-256 hashes; logout deletes them server-side. | `test_login_is_generic_and_locks_out`, `test_signup_rules`, `test_session_cookie_flags_and_logout` |
| 9 | **IDOR** | Every lookup is scoped to the signed-in user; foreign and unknown ids both return 404; scan ids are 128-bit random. | `test_users_cannot_access_each_others_data` |
| 10 | **Abuse / resource exhaustion** | Form field length limits, request-template size limit, bounded queue and worker pool, per-user daily quota, per-target RPS limit, response size cap, uvicorn concurrency and header-size limits, data retention (default 30 days). | unit + integration tests |
| 11 | **Insecure deployment** | With `AGENTGUARD_ENV=production` the app refuses to start without a ≥32-char secret, an `https://` base URL, an invite code (≥12 chars) or explicit open sign-up, and with private/HTTP targets enabled. HSTS is sent in production. The container runs as uid 10001 with a root-owned, read-only virtualenv. | `test_production_settings_refuse_insecure_configuration`, CI web image smoke test |
| 12 | **Vulnerable dependencies / code** | `pip-audit`, `bandit`, CodeQL (`security-extended`), Dependabot, hadolint. | CI |

## What the scan can and cannot see

Black-box HTTP agents are tested with conversational attacks (prompt injection, jailbreaks,
system-prompt leakage, data exfiltration, insecure output, denial of wallet, package
hallucination, over-refusal; excessive agency if the endpoint reports its tool calls).
Indirect injection, memory and RAG poisoning need tools AgentGuard controls, so they are offered
for OpenAI-compatible targets, where AgentGuard runs the agent loop and the mock tools itself.

## Operating limits (by design)

* **Single instance.** The rate limiter and the scan queue live in process memory, and secrets
  are never persisted, so the service must run as one instance (the Render blueprint does).
  Scaling out requires a shared limiter (e.g. Redis) and an encrypted, short-lived secret
  hand-off to workers.
* **Custom domains.** CSRF origin checks compare against `AGENTGUARD_BASE_URL`; set it to the
  public URL users visit.
* **Proxy hops.** `AGENTGUARD_TRUSTED_PROXY_HOPS` (default 1) must equal the number of reverse
  proxies that append to `X-Forwarded-For`; otherwise per-IP rate limits can be evaded or shared.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
