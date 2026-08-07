import {
  BadRequestException,
  Injectable,
  PayloadTooLargeException,
  UnsupportedMediaTypeException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { FileSource } from '@kapea/contracts';
import {
  createCorrelationId,
  createEventId,
  createFileId,
  createQuarantineObjectKey,
  createScanId,
  createTraceId,
  sanitizeFilename,
} from '@kapea/common';
import { EVENT_VERSION } from '@kapea/contracts';
import { PrismaService } from '@kapea/database';
import { QueueService } from '@kapea/messaging';
import { MetricsService } from '@kapea/observability';
import { StorageService } from '@kapea/storage';
import Busboy from 'busboy';
import { createHash } from 'node:crypto';
import { extname } from 'node:path';
import { PassThrough, Transform } from 'node:stream';
import type { Request } from 'express';

export interface ScanUploadResponse {
  scanId: string;
  status: 'QUEUED';
  filename: string;
  message: string;
}

interface ParsedUpload {
  filename: string;
  mimeType: string | null;
  sizeBytes: number;
  sha256: string;
  objectKey: string;
}

@Injectable()
export class FilesService {
  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly storage: StorageService,
    private readonly queue: QueueService,
    private readonly metrics: MetricsService,
  ) {}

  async handleScanUpload(request: Request): Promise<ScanUploadResponse> {
    const maxUploadBytes = Number(
      this.config.get<string>('MAX_UPLOAD_BYTES', '104857600'),
    );

    const contentType = request.headers['content-type'];
    if (!contentType?.startsWith('multipart/form-data')) {
      throw new UnsupportedMediaTypeException(
        'Content-Type must be multipart/form-data',
      );
    }

    const parsed = await this.parseMultipartUpload(request, maxUploadBytes);
    const scanId = createScanId();
    const fileId = createFileId();
    const correlationId = createCorrelationId();
    const traceId = createTraceId();
    const bucket = this.storage.getDefaultBucket();
    const sanitizedFilename = sanitizeFilename(parsed.filename);
    const extension = extname(sanitizedFilename).replace(/^\./, '') || null;

    await this.prisma.$transaction(async (tx) => {
      await tx.file.create({
        data: {
          id: fileId,
          originalFilename: parsed.filename,
          sanitizedFilename,
          storageBucket: bucket,
          storageKey: parsed.objectKey,
          sizeBytes: BigInt(parsed.sizeBytes),
          claimedMimeType: parsed.mimeType,
          extension,
          sha256: parsed.sha256,
          source: FileSource.WEB_API,
        },
      });

      await tx.scanJob.create({
        data: {
          id: scanId,
          fileId,
          status: 'QUEUED',
          progress: 0,
        },
      });
    });

    await this.queue.enqueueScanRequested({
      eventId: createEventId(),
      eventType: 'scan.requested',
      eventVersion: EVENT_VERSION,
      occurredAt: new Date().toISOString(),
      correlationId,
      scanId,
      fileId,
      traceId,
      storage: {
        bucket,
        objectKey: parsed.objectKey,
      },
      expectedSizeBytes: parsed.sizeBytes,
      expectedSha256: parsed.sha256,
      originalFilename: sanitizedFilename,
      claimedMimeType: parsed.mimeType,
      limits: {
        maxExtractedBytes: Number(
          this.config.get<string>('SCAN_MAX_EXTRACTED_BYTES', '524288000'),
        ),
        maxFiles: Number(this.config.get<string>('SCAN_MAX_FILES', '1000')),
        maxDepth: Number(this.config.get<string>('SCAN_MAX_DEPTH', '5')),
        timeoutSeconds: Number(
          this.config.get<string>('SCAN_TIMEOUT_SECONDS', '60'),
        ),
      },
    });

    this.metrics.recordUpload('web_api');
    this.metrics.recordScanQueued();

    return {
      scanId,
      status: 'QUEUED',
      filename: sanitizedFilename,
      message: 'The file was accepted and queued for scanning.',
    };
  }

  private parseMultipartUpload(
    request: Request,
    maxUploadBytes: number,
  ): Promise<ParsedUpload> {
    return new Promise((resolve, reject) => {
      const busboy = Busboy({
        headers: request.headers,
        limits: { files: 1, fileSize: maxUploadBytes },
      });

      let fileHandled = false;
      let resolved = false;

      const fail = (err: Error) => {
        if (resolved) {
          return;
        }
        resolved = true;
        reject(err);
      };

      busboy.on('file', (fieldname, fileStream, info) => {
        if (fieldname !== 'file') {
          fileStream.resume();
          return;
        }

        if (fileHandled) {
          fileStream.resume();
          fail(new BadRequestException('Only one file field is allowed'));
          return;
        }

        fileHandled = true;
        const filename = info.filename || 'unnamed';
        const mimeType = info.mimeType || null;
        const hash = createHash('sha256');
        const objectKey = createQuarantineObjectKey();
        let sizeBytes = 0;

        const countingStream = new Transform({
          transform(chunk: Buffer, _encoding, callback) {
            sizeBytes += chunk.length;
            if (sizeBytes > maxUploadBytes) {
              callback(new PayloadTooLargeException('File exceeds size limit'));
              return;
            }
            hash.update(chunk);
            callback(null, chunk);
          },
        });

        const uploadBody = new PassThrough();
        fileStream.pipe(countingStream).pipe(uploadBody);

        const bucket = this.storage.getDefaultBucket();
        const uploadPromise = this.storage.putObject({
          bucket,
          key: objectKey,
          body: uploadBody,
          contentType: mimeType ?? undefined,
        });

        fileStream.on('limit', () => {
          fail(new PayloadTooLargeException('File exceeds size limit'));
        });

        fileStream.on('error', fail);
        countingStream.on('error', fail);
        uploadBody.on('error', fail);

        uploadBody.on('finish', () => {
          void uploadPromise
            .then(() => {
              if (resolved) {
                return;
              }
              resolved = true;
              resolve({
                filename,
                mimeType,
                sizeBytes,
                sha256: hash.digest('hex'),
                objectKey,
              });
            })
            .catch(fail);
        });
      });

      busboy.on('field', () => {
        // Ignore non-file fields for Phase 1.
      });

      busboy.on('error', fail);

      busboy.on('close', () => {
        if (!fileHandled && !resolved) {
          fail(new BadRequestException('Missing required file field'));
        }
      });

      request.pipe(busboy);
    });
  }
}
