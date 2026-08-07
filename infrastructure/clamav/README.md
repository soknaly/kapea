# ClamAV notes

Local Compose uses `clamav/clamav-debian:stable` (multi-arch: amd64 + arm64).

The Alpine image `clamav/clamav` is **amd64-only** and fails to pull on Apple Silicon
with `no matching manifest for linux/arm64/v8`.

clamd listens on port **3310**. Freshclam may take several minutes on first start
while signature databases download.
