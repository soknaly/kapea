# Deployment

## Local development

Run infrastructure only:

```bash
pnpm docker:up
```

Or run individual NestJS apps with `pnpm dev:*` against local Postgres/Redis/MinIO.

## Docker Compose (full stack)

All application services have Dockerfiles under `infrastructure/docker/` and are wired in `infrastructure/docker/docker-compose.yml`.

```bash
docker compose -f infrastructure/docker/docker-compose.yml up -d --build
```

Build context is the **repository root**. Example single-service build:

```bash
docker build -f infrastructure/docker/Dockerfile.api -t kapea-api .
```

Environment variables come from `.env` (see `.env.example`). Compose overrides hostnames for in-network services (`postgres`, `redis`, `minio`, `clamav`, etc.).

The API container runs `prisma migrate deploy` on startup (disable with `RUN_MIGRATIONS=false`).

## Kubernetes

Production manifests live in `infrastructure/kubernetes/`:

- `namespace.yaml` — `kapea` namespace
- `configmap.yaml` / `secret.example.yaml` — non-secret and secret config
- Deployments for api, result-consumer, retention-worker, rust-scan-worker
- `deployment-api.yaml` includes a ClusterIP Service
- `hpa.yaml` — CPU-based autoscaling for API and scan workers
- `networkpolicy.yaml` — workers egress to ClamAV/Redis/storage; no public ingress to workers
- `seccomp/scan-worker.json` — restrictive syscall profile for scan workers

See [infrastructure/kubernetes/README.md](../infrastructure/kubernetes/README.md) for apply order and image build/push instructions.

Replace `REGISTRY` placeholders in deployment manifests with your container registry.

### BullMQ / Redis

Scan jobs use BullMQ backed by Redis (`REDIS_URL`). Queue: `scan-jobs`. Job name: `scan.requested`. Progress and completion are BullMQ job lifecycle/progress/return values — no separate queue-init job is required.

### Observability

- Prometheus scrapes `api:3000/metrics` (see `infrastructure/prometheus/prometheus.yml`)
- Grafana dashboard: `infrastructure/grafana/dashboards/kapea.json`
- Optional Sentry: set `SENTRY_DSN` on the API

### CI

GitHub Actions workflow `.github/workflows/ci.yml` runs pnpm build/test and `cargo test`. Dependabot config tracks npm, Cargo, and GitHub Actions updates.

## Integration testing

```bash
./scripts/e2e-smoke.sh
```

Requires the compose stack (or equivalent) with API reachable at `http://localhost:3000`.
