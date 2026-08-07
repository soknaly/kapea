# Architecture

KAPEA separates a NestJS **control plane** from a Rust **scanning plane**.

```text
Client / Telegram
        │
        ▼
   NestJS API ──► PostgreSQL
        │
        ├──► MinIO quarantine (private)
        │
        ▼
  BullMQ (Redis) — queue: scan-jobs
                 — job:   scan.requested
        │
        ▼
  Rust scan-worker (restricted)
        │
        ├── hashing, file-type, ClamAV, YARA, analyzers
        │
        ▼
  BullMQ job progress / return value (completed | failed)
        │
        ▼
  NestJS result-consumer ──► PostgreSQL
```

## System of record

NestJS owns scan lifecycle state. The Rust worker reports structured progress and results via BullMQ job progress and return values; NestJS validates and persists them.

## Queue / job contracts

| Queue / job | Producer | Consumer |
|-------------|----------|----------|
| `scan-jobs` / `scan.requested` | API / Telegram | Rust worker |

Payload schemas for the job data and result return values live in `packages/contracts` (TypeScript/Zod) and are mirrored in Rust models. Progress stages and completion/failure outcomes use BullMQ job lifecycle APIs rather than separate pub/sub subjects.
