# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.x | ✅ |

## Reporting a vulnerability

Please report vulnerabilities in AgentGuard itself (for example: a detector bypass that causes a
false "pass", unsafe handling of target output in reports or the dashboard, or a sandbox escape in
the mock tools) **privately** via GitHub's "Report a vulnerability" (Security → Advisories) on
https://github.com/PiyushDas-2004/agentguard. Do not open a public issue.

Include a minimal reproduction (config + dataset case), the AgentGuard version (`agentguard
--version`) and the impact. We aim to acknowledge reports within 3 business days and to ship a
fix or mitigation within 30 days for high-severity issues.

## Hardening notes

* Reports HTML-escape all target output (Jinja2 autoescape) and load no external resources.
* The dashboard binds to `127.0.0.1` by default; expose it only behind authentication.
* The container runs as a non-root user (`uid 10001`).
* Live provider keys are read from environment variables only and never written to reports.
