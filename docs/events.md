# Event contracts

Scan work is queued with **BullMQ** on Redis (`REDIS_URL`).

| Item | Value |
|------|-------|
| Queue | `scan-jobs` |
| Job name | `scan.requested` |
| Progress | BullMQ job `progress` updates |
| Completion | BullMQ job return value |
| Failure | BullMQ failed job / error |

Job payloads and result shapes include: `eventId`, `eventType`, `eventVersion`, `occurredAt`, `correlationId`, `scanId`, `fileId`, `traceId` (and related scan fields).

Canonical TypeScript schemas: `@kapea/contracts`.

JSON Schema copies: `packages/contracts/schemas/`.

## scan.requested (job data)

Enqueued after a file is successfully written to quarantine. Job name is `scan.requested` on queue `scan-jobs`.

## Progress

Informational stage updates published via BullMQ job progress. Not a transaction boundary.

## Completed

Job return value contains hashes, findings, risk score, automated verdict, scanner versions, and timing.

## Failed

Normalized `errorCode` + safe `errorMessage` on job failure. May be retryable via BullMQ retry policy.
