# API Rate Limits

The Acme Cloud REST API limits the number of requests each workspace can make. Limits apply per workspace and are shared by all API keys in that workspace.

The Starter plan allows 120 requests per minute. The Team plan allows 600 requests per minute. The Business plan allows 1,200 requests per minute, and the Enterprise plan allows 6,000 requests per minute. Short bursts of up to twice the per-minute limit are allowed for 10 seconds.

Requests over the limit receive the HTTP 429 Too Many Requests status code. The response carries a Retry-After header with the number of seconds to wait. Every response also carries X-RateLimit-Limit, X-RateLimit-Remaining and X-RateLimit-Reset headers.

Bulk export endpoints have a separate limit of 10 concurrent export jobs per workspace. Webhook deliveries do not count toward the rate limit.

Well-behaved clients retry with exponential backoff and jitter, starting at 1 second. Enterprise customers can request a temporary limit increase for migrations through their account manager; increases are approved for up to 14 days. Workspaces that exceed the limit continuously for more than one hour may be throttled further until traffic returns to normal levels.
