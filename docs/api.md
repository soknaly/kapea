# API

Base path: `/api/v1`  
Health and metrics are outside the versioned prefix: `/health/*`, `/metrics`.

OpenAPI/Swagger: `/api/docs`

Authentication:

- Client endpoints: optional `X-API-Key` when `REQUIRE_API_KEY=true`
- Admin endpoints: required `X-Admin-Key` (`ADMIN_API_KEY`)

## Client

| Method | Path | Description |
|--------|------|-------------|
| POST | `/files/scan` | Stream upload → quarantine → queue scan |
| GET | `/scans/:scanId` | Status + progress |
| GET | `/scans/:scanId/result` | Final report |
| DELETE | `/scans/:scanId/file` | Delete quarantined object when policy allows |

## Admin

All admin routes require header `X-Admin-Key: <ADMIN_API_KEY>`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/scans` | List/search scan jobs (`status`, `limit`, `cursor` query params) |
| GET | `/admin/scans/:scanId` | Full technical scan report |
| POST | `/admin/scans/:scanId/retry` | Retry a failed or stuck scan |
| POST | `/admin/scans/:scanId/override` | Override displayed verdict |
| DELETE | `/admin/scans/:scanId/file` | Force delete quarantined file |
| GET | `/admin/scanners` | List scanner engine definitions |
| PATCH | `/admin/scanners/:engine` | Enable/disable a scanner engine |
| GET | `/admin/yara-rules` | List YARA rule file metadata |
| POST | `/admin/yara-rules/validate` | Validate YARA rule text |
| POST | `/admin/yara-rules/deploy` | Deploy a YARA rule file |
| GET | `/admin/audit-logs` | List audit logs (`limit`, `cursor`) |
| GET | `/admin/health` | Detailed admin health (DB, Redis, storage) |

## Health

| Method | Path |
|--------|------|
| GET | `/health/live` |
| GET | `/health/ready` |
| GET | `/health/scanners` |

## Metrics

| Method | Path | Description |
|--------|------|-------------|
| GET | `/metrics` | Prometheus text exposition (uploads, scans queued/completed) |

Optional error tracking: set `SENTRY_DSN` to enable Sentry in the API process.
