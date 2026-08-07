import { Storage } from '@google-cloud/storage';
import { Logger } from '@nestjs/common';
import { Readable } from 'node:stream';
import {
  DeleteObjectParams,
  GetObjectParams,
  HeadObjectParams,
  HeadObjectResult,
  ObjectStorage,
  PutObjectParams,
  StorageProvider,
} from '../storage.types';

export interface GcsConfig {
  projectId?: string;
  /** Absolute path to service-account JSON, or omit for ADC */
  keyFilename?: string;
  /** Inline service-account JSON string */
  credentialsJson?: string;
}

/**
 * Google Cloud Storage adapter for private quarantine buckets.
 */
export class GcsAdapter implements ObjectStorage {
  readonly provider: StorageProvider = 'gcs';
  private readonly logger = new Logger(GcsAdapter.name);
  private readonly client: Storage;

  constructor(config: GcsConfig) {
    const options: ConstructorParameters<typeof Storage>[0] = {
      projectId: config.projectId,
    };

    if (config.keyFilename) {
      options.keyFilename = config.keyFilename;
    } else if (config.credentialsJson) {
      options.credentials = JSON.parse(config.credentialsJson) as object;
    }

    this.client = new Storage(options);
  }

  async putObject(params: PutObjectParams): Promise<void> {
    const file = this.client.bucket(params.bucket).file(params.key);
    const writeStream = file.createWriteStream({
      resumable: false,
      contentType: params.contentType,
      metadata: {
        contentType: params.contentType,
      },
      predefinedAcl: 'private',
    });

    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => reject(err);
      writeStream.on('error', onError);
      writeStream.on('finish', () => resolve());

      if (Buffer.isBuffer(params.body)) {
        writeStream.end(params.body);
      } else {
        params.body.pipe(writeStream);
      }
    });
  }

  async getObjectStream(params: GetObjectParams): Promise<Readable> {
    const file = this.client.bucket(params.bucket).file(params.key);
    const [exists] = await file.exists();
    if (!exists) {
      throw new Error(`Object not found: ${params.bucket}/${params.key}`);
    }
    return file.createReadStream();
  }

  async deleteObject(params: DeleteObjectParams): Promise<void> {
    await this.client.bucket(params.bucket).file(params.key).delete({
      ignoreNotFound: true,
    });
  }

  async ensureBucket(bucket: string): Promise<void> {
    const b = this.client.bucket(bucket);
    const [exists] = await b.exists();
    if (!exists) {
      this.logger.log(`Creating GCS bucket ${bucket}`);
      await this.client.createBucket(bucket, {
        iamConfiguration: {
          uniformBucketLevelAccess: { enabled: true },
        },
      });
    }
  }

  async headObject(params: HeadObjectParams): Promise<HeadObjectResult | null> {
    try {
      const [metadata] = await this.client
        .bucket(params.bucket)
        .file(params.key)
        .getMetadata();
      return {
        contentLength: metadata.size ? Number(metadata.size) : undefined,
        contentType: metadata.contentType,
        etag: metadata.etag,
      };
    } catch {
      return null;
    }
  }
}
