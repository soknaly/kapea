import { Readable } from 'node:stream';

export type StorageProvider = 'minio' | 's3' | 'gcs' | 'azure';

export interface PutObjectParams {
  bucket: string;
  key: string;
  body: Readable | Buffer;
  contentType?: string;
  contentLength?: number;
}

export interface GetObjectParams {
  bucket: string;
  key: string;
}

export interface DeleteObjectParams {
  bucket: string;
  key: string;
}

export interface HeadObjectParams {
  bucket: string;
  key: string;
}

export interface HeadObjectResult {
  contentLength?: number;
  contentType?: string;
  etag?: string;
}

/**
 * Private quarantine object-storage contract.
 * Implementations must never expose public URLs.
 */
export interface ObjectStorage {
  readonly provider: StorageProvider;

  putObject(params: PutObjectParams): Promise<void>;
  getObjectStream(params: GetObjectParams): Promise<Readable>;
  deleteObject(params: DeleteObjectParams): Promise<void>;
  ensureBucket(bucket: string): Promise<void>;
  headObject?(params: HeadObjectParams): Promise<HeadObjectResult | null>;
}

export const OBJECT_STORAGE = Symbol('OBJECT_STORAGE');
