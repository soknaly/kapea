import {
  CreateBucketCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
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

export interface S3CompatibleConfig {
  provider: 'minio' | 's3';
  region: string;
  endpoint?: string;
  accessKeyId: string;
  secretAccessKey: string;
  forcePathStyle?: boolean;
}

/**
 * AWS S3 and MinIO (S3-compatible) adapter.
 * MinIO uses path-style addressing and a custom endpoint.
 */
export class S3CompatibleAdapter implements ObjectStorage {
  readonly provider: StorageProvider;
  private readonly logger = new Logger(S3CompatibleAdapter.name);
  private readonly client: S3Client;

  constructor(private readonly config: S3CompatibleConfig) {
    this.provider = config.provider;
    this.client = new S3Client({
      region: config.region,
      endpoint: config.endpoint,
      forcePathStyle: config.forcePathStyle ?? config.provider === 'minio',
      credentials: {
        accessKeyId: config.accessKeyId,
        secretAccessKey: config.secretAccessKey,
      },
    });
  }

  async putObject(params: PutObjectParams): Promise<void> {
    const upload = new Upload({
      client: this.client,
      params: {
        Bucket: params.bucket,
        Key: params.key,
        Body: params.body,
        ContentType: params.contentType,
        ContentLength: params.contentLength,
      },
    });
    await upload.done();
  }

  async getObjectStream(params: GetObjectParams): Promise<Readable> {
    const response = await this.client.send(
      new GetObjectCommand({
        Bucket: params.bucket,
        Key: params.key,
      }),
    );
    if (!response.Body) {
      throw new Error(`Object not found: ${params.bucket}/${params.key}`);
    }
    return response.Body as Readable;
  }

  async deleteObject(params: DeleteObjectParams): Promise<void> {
    await this.client.send(
      new DeleteObjectCommand({
        Bucket: params.bucket,
        Key: params.key,
      }),
    );
  }

  async ensureBucket(bucket: string): Promise<void> {
    try {
      await this.client.send(new HeadBucketCommand({ Bucket: bucket }));
    } catch {
      this.logger.log(`Creating bucket ${bucket} (${this.provider})`);
      await this.client.send(new CreateBucketCommand({ Bucket: bucket }));
    }
  }

  async headObject(params: HeadObjectParams): Promise<HeadObjectResult | null> {
    try {
      const result = await this.client.send(
        new HeadObjectCommand({
          Bucket: params.bucket,
          Key: params.key,
        }),
      );
      return {
        contentLength: result.ContentLength,
        contentType: result.ContentType,
        etag: result.ETag,
      };
    } catch {
      return null;
    }
  }

  async putBuffer(
    bucket: string,
    key: string,
    body: Buffer,
    contentType?: string,
  ): Promise<void> {
    await this.client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: body,
        ContentType: contentType,
      }),
    );
  }
}
