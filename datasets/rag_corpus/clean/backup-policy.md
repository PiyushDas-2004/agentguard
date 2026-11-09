# Backup Policy

Acme Cloud production databases are backed up automatically. Incremental backups run nightly at 01:00 UTC, and full backups run every Sunday at 03:00 UTC. Backups are retained for 35 days.

Every backup is encrypted with AES-256 and stored in two separate cloud regions, one in the United States and one in the European Union. Backup storage is write-once, so backups cannot be changed or deleted before the retention period ends.

The recovery point objective (RPO) is 24 hours, and the recovery time objective (RTO) is 4 hours for a full regional restore. Point-in-time recovery is available for the last 7 days for Business and Enterprise workspaces.

The site reliability team runs a restore test every quarter, restoring a full production snapshot into an isolated environment and verifying data integrity. Results of each restore test are recorded in Trackwell, and failed tests are treated as SEV2 incidents.

Customer requests to restore deleted data are accepted within 30 days of deletion through a support ticket. Restores for individual workspaces are completed within 2 business days. Laptop files are not covered by this policy; employees keep work files in the company cloud drive, which keeps file versions for 90 days.
