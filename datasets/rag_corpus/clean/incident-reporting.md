# Incident Reporting

Acme Corp classifies production incidents into four severity levels. SEV1 is a full outage or data loss affecting customers. SEV2 is a major feature degraded for many customers. SEV3 is a minor feature impaired with a workaround available. SEV4 is a cosmetic or internal-only issue.

Any employee who notices a possible incident reports it in the #incidents Slack channel or through the incident form in Trackwell. The on-call engineer acknowledges SEV1 and SEV2 pages within 5 minutes and becomes the incident commander until a more senior responder takes over.

For SEV1 incidents, the status page is updated within 15 minutes of detection and then every 30 minutes until resolution. Enterprise customers affected by a SEV1 incident receive a direct notice from their account manager within 1 hour.

Security incidents, including suspected credential exposure or phishing, are reported to the security team within 1 hour of discovery, even outside business hours.

Every SEV1 and SEV2 incident gets a blameless postmortem within 5 business days. The postmortem records the timeline, root cause, customer impact and follow-up actions, and each action has an owner and a due date in Trackwell.
