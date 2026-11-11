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
| 8 | **Account takeover / credential stuffing** | argon2id hashes on a dedicated 4-thread pool (bounds CPU and resident memory under a login flood); minimum 12-character passwords with common/self-referential checks; generic error messages and constant-time dummy verification for unknown e-mails; throttling per client (IPv6 grouped by /64), per (account, client) and globally — deliberately **no per-account lockout**, so knowing someone's e-mail does not let you lock them out; invite-code sign-up by default. Sessions are random 256-bit tokens stored only as SHA-256 hashes; logout deletes them server-side. | `test_login_is_generic_and_throttled_per_client`, `test_signup_rules`, `test_session_cookie_flags_and_logout` |
| 9 | **IDOR** | Every lookup is scoped to the signed-in user; foreign and unknown ids both return 404; scan ids are 128-bit random. | `test_users_cannot_access_each_others_data` |
| 10 | **Abuse / resource exhaustion** | Request bodies capped at 64 KiB before parsing (declared and chunked); form field limits; bounded queue and worker pool; one active scan per user; a daily quota counted from the append-only audit log (deleting scans does not refund it); a total time limit per scan (default 30 min) plus per-turn timeouts; per-target RPS limit; target responses capped at 256 KiB and **compressed responses refused** (no decompression bombs); at most 50 reported tool calls and 8,000 reply characters kept per turn; stored results capped at 5 MB (transcripts dropped first, aggregates kept); hourly purge of expired scans, audit events and sessions; failed-login audit rows only for existing accounts. | `test_oversized_request_bodies_are_rejected_before_parsing`, `test_deleting_scans_does_not_refund_the_daily_quota`, `test_scans_have_a_total_time_limit`, `test_stored_results_are_bounded`, `test_cancelling_a_running_scan_stops_it`, `test_compressed_responses_are_refused` |
| 11 | **Insecure deployment** | With `AGENTGUARD_ENV=production` the app refuses to start without a ≥32-char secret, an `https://` base URL, an invite code (≥12 chars) or explicit open sign-up, and with private/HTTP targets enabled. HSTS is sent in production. The container runs as uid 10001 with a root-owned, read-only virtualenv. | `test_production_settings_refuse_insecure_configuration`, CI web image smoke test |
| 12 | **Administrator actions** | `/admin` is available only to `AGENTGUARD_ADMIN_EMAILS` (404 for everyone else). Disabling a user signs them out everywhere and cancels their scans; password resets issue a one-time temporary password that is shown once and stored only as an argon2 hash. Every admin action is audited. Sign up with the admin e-mail **before** sharing the invite code, because admin rights follow the e-mail address. | `test_admin_area_and_user_disabling`, `test_change_password_and_admin_reset` |
| 13 | **Secrets in logs and error reports** | Logs are redacted JSON lines without query strings or bodies; error stacks contain frame locations only. Sentry (optional) runs with `send_default_pii=False`, no request bodies, no local variables, and a scrubber that drops cookies/headers/query strings and redacts every string. | `tests/unit/web/test_observability.py` |
| 14 | **Vulnerable dependencies / code** | `pip-audit`, `bandit`, CodeQL (`security-extended`), Dependabot, hadolint. | CI |

## What the scan can and cannot see

Black-box HTTP agents are tested with conversational attacks (prompt injection, jailbreaks,
system-prompt leakage, data exfiltration, insecure output, denial of wallet, package
hallucination, over-refusal; excessive agency if the endpoint reports its tool calls).
Indirect injection, memory and RAG poisoning need tools AgentGuard controls, so they are offered
for OpenAI-compatible targets, where AgentGuard runs the agent loop and the mock tools itself.

## Independent review

The app was reviewed adversarially before release. No SSRF, XSS, CSRF, IDOR or cross-tenant
secret leak was found; the review found resource-exhaustion issues (unbounded result size,
request bodies, gzip responses, argon2 memory under a login flood), an account-lockout DoS, a
quota refund via deletion, no total scan time limit, unbounded audit growth, JSON-escaped secrets
escaping redaction, and the deprecated `fec0::/10` range being treated as public. All were fixed
and each has a regression test (listed above). Fixing them also exposed that cancelling a running
scan did not stop it (the CLI scheduler converts cancellation into a partial result); cancellation
and the time limit are now enforced around the scan task.

## Operating limits (by design)

* **Single instance.** The rate limiter and the scan queue live in process memory, and secrets
  are never persisted, so the service must run as one instance (the Render blueprint does).
  Scaling out requires a shared limiter (e.g. Redis) and an encrypted, short-lived secret
  hand-off to workers.
* **Custom domains.** CSRF origin checks compare against `AGENTGUARD_BASE_URL`; set it to the
  public URL users visit.
* **Proxy hops.** `AGENTGUARD_TRUSTED_PROXY_HOPS` (default 1) must equal the number of reverse
  proxies that append to `X-Forwarded-For`; otherwise per-IP rate limits can be evaded or shared.
  On a new deployment, confirm it once on the admin page: *Connection check* shows the address
  the app sees for you; it must equal your real public IP. If your platform puts the client IP in
  a dedicated header (e.g. `True-Client-IP`), set `AGENTGUARD_CLIENT_IP_HEADER`.
* **Account enumeration at sign-up.** Sign-up says when an e-mail is already registered. This is
  limited by the invite code and the sign-up rate limit; an open-sign-up deployment that needs to
  hide it should add e-mail verification.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
