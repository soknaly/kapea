import { ConfigService } from '@nestjs/config';
import { AzureBlobAdapter } from './adapters/azure.adapter';
import { GcsAdapter } from './adapters/gcs.adapter';
import { S3CompatibleAdapter } from './adapters/s3.adapter';
import { ObjectStorage, StorageProvider } from './storage.types';

export function resolveStorageProvider(
  config: ConfigService,
): StorageProvider {
  const raw = (
    config.get<string>('STORAGE_PROVIDER') ?? 'minio'
  ).toLowerCase();

  if (raw === 'minio' || raw === 's3' || raw === 'gcs' || raw === 'azure') {
    return raw;
  }

  throw new Error(
    `Unsupported STORAGE_PROVIDER="${raw}". Use minio | s3 | gcs | azure.`,
  );
}

export function createObjectStorage(config: ConfigService): ObjectStorage {
  const provider = resolveStorageProvider(config);

  switch (provider) {
    case 'minio':
      return new S3CompatibleAdapter({
        provider: 'minio',
        region: config.get<string>('S3_REGION', 'us-east-1'),
        endpoint: config.getOrThrow<string>('S3_ENDPOINT'),
        accessKeyId: config.getOrThrow<string>('S3_ACCESS_KEY'),
        secretAccessKey: config.getOrThrow<string>('S3_SECRET_KEY'),
        forcePathStyle:
          config.get<string>('S3_FORCE_PATH_STYLE', 'true') === 'true',
      });

    case 's3':
      return new S3CompatibleAdapter({
        provider: 's3',
        region: config.getOrThrow<string>('S3_REGION'),
        endpoint: config.get<string>('S3_ENDPOINT') || undefined,
        accessKeyId: config.getOrThrow<string>('S3_ACCESS_KEY'),
        secretAccessKey: config.getOrThrow<string>('S3_SECRET_KEY'),
        forcePathStyle:
          config.get<string>('S3_FORCE_PATH_STYLE', 'false') === 'true',
      });

    case 'gcs':
      return new GcsAdapter({
        projectId: config.get<string>('GCS_PROJECT_ID'),
        keyFilename: config.get<string>('GCS_KEY_FILENAME'),
        credentialsJson: config.get<string>('GCS_CREDENTIALS_JSON'),
      });

    case 'azure':
      return new AzureBlobAdapter({
        accountName: config.get<string>('AZURE_STORAGE_ACCOUNT', ''),
        accountKey: config.get<string>('AZURE_STORAGE_KEY', ''),
        connectionString: config.get<string>('AZURE_STORAGE_CONNECTION_STRING'),
      });

    default: {
      const _exhaustive: never = provider;
      throw new Error(`Unhandled provider: ${_exhaustive}`);
    }
  }
}
