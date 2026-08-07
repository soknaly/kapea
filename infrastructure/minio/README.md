# MinIO seed notes

Compose service `minio-init` creates the private `quarantine` bucket with no public ACL.

Application services should call `StorageService.ensureBucket()` on startup as a safety net.
