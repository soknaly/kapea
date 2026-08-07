# Quarantine object storage

KAPEA stores uploaded files in a **private** quarantine bucket/container.
Original filenames are never used as object keys.

## Providers

Set `STORAGE_PROVIDER` to one of:

| Value | Backend | Notes |
|-------|---------|-------|
| `minio` | MinIO (local default) | S3 API + path-style endpoint |
| `s3` | AWS S3 | Standard AWS credentials / region |
| `gcs` | Google Cloud Storage | ADC, key file, or JSON credentials |
| `azure` | Azure Blob Storage | Account key or connection string |

NestJS resolves the adapter via `@kapea/storage` (`StorageModule`).
The Rust scan-worker uses the same `STORAGE_PROVIDER` env and S3-compatible
APIs for MinIO/S3; GCS uses the XML/S3 interoperability endpoint or native
client when configured.

## Security requirements

- No public ACLs / public URLs
- Server-generated random object keys
- Encryption at rest (provider-managed)
- Short-lived signed access only for workers when needed
- Deletion via retention policy + audit log
