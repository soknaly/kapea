# Security assumptions

1. Uploaded files are hostile until proven otherwise.
2. NestJS never parses or executes file contents for detection.
3. Rust workers run in restricted containers with disposable workdirs.
4. Quarantine buckets have no public ACLs.
5. Object keys are random — never derived from original filenames.
6. Incomplete or failed required scanners → `UNKNOWN` or `SCAN_FAILED`, never `CLEAN`.
7. External uploads (e.g. VirusTotal) require explicit policy approval.
8. Logs exclude file contents, secrets, and tokens.

## Worker isolation (Phase 6)

### Seccomp

Scan workers should run with a restrictive seccomp profile:

- **Docker Compose / Kubernetes:** `infrastructure/kubernetes/seccomp/scan-worker.json`
- Install on Kubernetes nodes at `/var/lib/kubelet/seccomp/kapea-scan-worker.json`
- Reference in pod `securityContext.seccompProfile.localhostProfile`

The profile allows network and file I/O needed for scanning while denying mount, module load, and most privilege escalation syscalls.

### AppArmor

An AppArmor profile stub is provided at `infrastructure/docker/scan-worker.apparmor`:

- Read-only access to `/rules/**` (YARA rules mount)
- Read/write to `/tmp/kapea/**` (disposable workdir)
- Network allowed for Redis (BullMQ), ClamAV, and object storage
- Execution denied on files under the workdir (`deny ... ix`)

Load on the host and attach via Docker `security_opt` or Kubernetes AppArmor annotations. Tune for your environment after a security audit.

### Network policies

Kubernetes `networkpolicy.yaml` restricts scan workers:

- **Egress:** ClamAV (3310), Redis (6379), MinIO/S3 (9000), DNS
- **Ingress:** denied for workers (no public exposure)

Control-plane services (API) accept ingress on port 3000 from allowed namespaces only.

## Observability secrets

- `SENTRY_DSN` is optional; when set, the API initializes Sentry without logging the DSN.
- Prometheus `/metrics` should not be exposed publicly without authentication in production.

## Dependency scanning

GitHub Dependabot (`.github/dependabot.yml`) and CI `pnpm audit` (non-blocking) provide baseline dependency visibility. Review and patch high-severity findings before production deploys.
