# Release Process

Acme Cloud ships on a two-week release train. Each release is numbered with a minor version, such as 2.4 or 2.5, and goes out on a Friday.

Code freeze is at 5:00 pm Eastern on the Wednesday before the release. After code freeze, only fixes for release-blocking bugs are merged, and each one needs approval from the release captain. The release captain rotates among senior engineers every release.

Release candidates are deployed to the staging environment on Thursday for regression testing and a final quality review. A release proceeds only when automated tests pass and no P0 or P1 bugs remain open for that release.

Production rollout is staged over 48 hours: 5% of workspaces on Friday morning, 25% on Friday afternoon and 100% by Sunday. Rollout is paused automatically when the error rate rises above 2% or the median API latency increases by more than 20%. Any rollout pause triggers a rollback decision by the release captain within 30 minutes.

Release notes are published in the help center on release day. Hotfixes for P0 bugs follow a shortened process with a single approval and ship outside the regular train.
