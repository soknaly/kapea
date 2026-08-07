import {
  BlobServiceClient,
  ContainerClient,
  StorageSharedKeyCredential,
} from '@azure/storage-blob';
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

export interface AzureConfig {
  accountName: string;
  accountKey: string;
  /** Optional full connection string overrides account name/key */
  connectionString?: string;
}

/**
 * Azure Blob Storage adapter. Buckets map to containers.
 */
export class AzureBlobAdapter implements ObjectStorage {
  readonly provider: StorageProvider = 'azure';
  private readonly logger = new Logger(AzureBlobAdapter.name);
  private readonly service: BlobServiceClient;

  constructor(config: AzureConfig) {
    if (config.connectionString) {
      this.service = BlobServiceClient.fromConnectionString(
        config.connectionString,
      );
    } else {
      const credential = new StorageSharedKeyCredential(
        config.accountName,
        config.accountKey,
      );
      this.service = new BlobServiceClient(
        `https://${config.accountName}.blob.core.windows.net`,
        credential,
      );
    }
  }

  private container(name: string): ContainerClient {
    return this.service.getContainerClient(name);
  }

  async putObject(params: PutObjectParams): Promise<void> {
    const blockBlob = this.container(params.bucket).getBlockBlobClient(
      params.key,
    );
    const options = {
      blobHTTPHeaders: params.contentType
        ? { blobContentType: params.contentType }
        : undefined,
    };

    if (Buffer.isBuffer(params.body)) {
      await blockBlob.uploadData(params.body, options);
    } else {
      await blockBlob.uploadStream(
        params.body,
        undefined,
        undefined,
        options,
      );
    }
  }

  async getObjectStream(params: GetObjectParams): Promise<Readable> {
    const blockBlob = this.container(params.bucket).getBlockBlobClient(
      params.key,
    );
    const download = await blockBlob.download(0);
    if (!download.readableStreamBody) {
      throw new Error(`Object not found: ${params.bucket}/${params.key}`);
    }
    return download.readableStreamBody as Readable;
  }

  async deleteObject(params: DeleteObjectParams): Promise<void> {
    await this.container(params.bucket)
      .getBlockBlobClient(params.key)
      .deleteIfExists();
  }

  async ensureBucket(bucket: string): Promise<void> {
    const container = this.container(bucket);
    const exists = await container.exists();
    if (!exists) {
      this.logger.log(`Creating Azure container ${bucket}`);
      await container.create({ access: undefined });
    }
  }

  async headObject(params: HeadObjectParams): Promise<HeadObjectResult | null> {
    try {
      const props = await this.container(params.bucket)
        .getBlockBlobClient(params.key)
        .getProperties();
      return {
        contentLength: props.contentLength,
        contentType: props.contentType,
        etag: props.etag,
      };
    } catch {
      return null;
    }
  }
}
