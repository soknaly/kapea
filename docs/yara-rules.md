# YARA rules

Local rules live in `infrastructure/yara/rules/`.

The Rust worker loads only validated rule packages and records the active package version on each scan result.

Do not deploy unreviewed community rules without validation.
