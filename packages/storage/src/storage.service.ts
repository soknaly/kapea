import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Readable } from 'node:stream';
import {
  DeleteObjectParams,
  GetObjectParams,
  HeadObjectParams,
  HeadObjectResult,
  OBJECT_STORAGE,
  ObjectStorage,
  PutObjectParams,
  StorageProvider,
} from './storage.types';

/**
 * Facade over the configured ObjectStorage adapter.
 * Prefer injecting this service in Nest apps.
 */
@Injectable()
export class StorageService implements ObjectStorage, OnModuleInit {
  private readonly logger = new Logger(StorageService.name);
  private readonly defaultBucket: string;

  constructor(
    @Inject(OBJECT_STORAGE) private readonly adapter: ObjectStorage,
    private readonly config: ConfigService,
  ) {
    this.defaultBucket = this.config.get<string>(
      'STORAGE_BUCKET',
      this.config.get<string>('S3_BUCKET', 'quarantine'),
    );
  }

  get provider(): StorageProvider {
    return this.adapter.provider;
  }

  async onModuleInit(): Promise<void> {
    this.logger.log(
      `Quarantine storage provider=${this.provider} bucket=${this.defaultBucket}`,
    );
    await this.ensureBucket(this.defaultBucket);
  }

  getDefaultBucket(): string {
    return this.defaultBucket;
  }

  putObject(params: PutObjectParams): Promise<void> {
    return this.adapter.putObject(params);
  }

  getObjectStream(params: GetObjectParams): Promise<Readable> {
    return this.adapter.getObjectStream(params);
  }

  deleteObject(params: DeleteObjectParams): Promise<void> {
    return this.adapter.deleteObject(params);
  }

  ensureBucket(bucket: string): Promise<void> {
    return this.adapter.ensureBucket(bucket);
  }

  headObject(params: HeadObjectParams): Promise<HeadObjectResult | null> {
    if (this.adapter.headObject) {
      return this.adapter.headObject(params);
    }
    return Promise.resolve(null);
  }
}
