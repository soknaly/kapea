import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ScanCompletedEvent,
  ScanFailedEvent,
  ScanProgressEvent,
  ScanRequestedEvent,
  ScanRequestedEventSchema,
} from '@kapea/contracts';
import { Queue, QueueEvents } from 'bullmq';

export const SCAN_QUEUE_NAME = 'scan-jobs';
export const SCAN_REQUESTED_JOB_NAME = 'scan.requested';

const REMOVE_ON_COMPLETE = {
  age: 24 * 60 * 60,
  count: 1_000,
};

export type QueueEventHandler<T> = (data: T) => Promise<void> | void;

@Injectable()
export class QueueService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(QueueService.name);
  private readonly progressHandlers = new Set<
    QueueEventHandler<ScanProgressEvent>
  >();
  private readonly completedHandlers = new Set<
    QueueEventHandler<ScanCompletedEvent>
  >();
  private readonly failedHandlers = new Set<
    QueueEventHandler<ScanFailedEvent>
  >();
  private queue: Queue<ScanRequestedEvent, ScanCompletedEvent> | null = null;
  private queueEvents: QueueEvents | null = null;

  constructor(private readonly config: ConfigService) {}

  async onModuleInit(): Promise<void> {
    const redisUrl = this.config.get<string>(
      'REDIS_URL',
      'redis://localhost:6379',
    );
    const connection = this.parseRedisUrl(redisUrl);

    this.queue = new Queue<ScanRequestedEvent, ScanCompletedEvent>(
      SCAN_QUEUE_NAME,
      { connection },
    );
    this.queueEvents = new QueueEvents(SCAN_QUEUE_NAME, { connection });

    this.queueEvents.on('progress', ({ data }) => {
      void this.dispatch(this.progressHandlers, this.parsePayload(data));
    });
    this.queueEvents.on('completed', ({ returnvalue }) => {
      void this.dispatch(
        this.completedHandlers,
        this.parsePayload(returnvalue),
      );
    });
    this.queueEvents.on('failed', ({ jobId, failedReason }) => {
      void this.handleInfrastructureFailure(jobId, failedReason);
    });
    this.queueEvents.on('error', (error) => {
      this.logger.error('BullMQ QueueEvents error', error);
    });

    await Promise.all([
      this.queue.waitUntilReady(),
      this.queueEvents.waitUntilReady(),
    ]);
    this.logger.log(`Connected to BullMQ queue ${SCAN_QUEUE_NAME}`);
  }

  async onModuleDestroy(): Promise<void> {
    await Promise.all([this.queueEvents?.close(), this.queue?.close()]);
    this.queueEvents = null;
    this.queue = null;
  }

  async enqueueScanRequested(event: ScanRequestedEvent): Promise<void> {
    const validated = ScanRequestedEventSchema.parse(event);
    const queue = this.requireQueue();

    await queue.add(SCAN_REQUESTED_JOB_NAME, validated, {
      jobId: validated.eventId,
      attempts: 5,
      backoff: {
        type: 'exponential',
        delay: 1_000,
      },
      removeOnComplete: REMOVE_ON_COMPLETE,
    });
  }

  async isConnected(): Promise<boolean> {
    if (!this.queue) {
      return false;
    }

    try {
      // BullMQ v6 hides the raw Redis client; a lightweight queue call is enough.
      await this.queue.getJobCounts('wait');
      return true;
    } catch {
      return false;
    }
  }

  onScanProgress(handler: QueueEventHandler<ScanProgressEvent>): () => void {
    this.progressHandlers.add(handler);
    return () => this.progressHandlers.delete(handler);
  }

  onScanCompleted(handler: QueueEventHandler<ScanCompletedEvent>): () => void {
    this.completedHandlers.add(handler);
    return () => this.completedHandlers.delete(handler);
  }

  onScanFailed(handler: QueueEventHandler<ScanFailedEvent>): () => void {
    this.failedHandlers.add(handler);
    return () => this.failedHandlers.delete(handler);
  }

  private requireQueue(): Queue<ScanRequestedEvent, ScanCompletedEvent> {
    if (!this.queue) {
      throw new Error('BullMQ scan queue is not initialized');
    }
    return this.queue;
  }

  private async handleInfrastructureFailure(
    jobId: string,
    failedReason: string,
  ): Promise<void> {
    try {
      const job = await this.requireQueue().getJob(jobId);
      if (!job) {
        this.logger.warn(`Failed BullMQ job ${jobId} is no longer available`);
        return;
      }

      const attempts = job.opts.attempts ?? 1;
      if (job.attemptsMade < attempts) {
        return;
      }

      const request = ScanRequestedEventSchema.parse(job.data);
      await this.dispatch(this.failedHandlers, {
        eventId: `${request.eventId}-failed`,
        eventType: 'scan.failed',
        eventVersion: 1,
        occurredAt: new Date().toISOString(),
        correlationId: request.correlationId,
        scanId: request.scanId,
        fileId: request.fileId,
        traceId: request.traceId,
        errorCode: 'WORKER_INFRASTRUCTURE_FAILURE',
        errorMessage: failedReason || 'BullMQ worker failed without a reason',
        retryable: false,
      });
    } catch (error) {
      this.logger.error(`Failed to process BullMQ failure for ${jobId}`, error);
    }
  }

  private async dispatch<T>(
    handlers: Set<QueueEventHandler<T>>,
    payload: unknown,
  ): Promise<void> {
    for (const handler of handlers) {
      try {
        await handler(payload as T);
      } catch (error) {
        this.logger.error('BullMQ event handler failed', error);
      }
    }
  }

  private parsePayload(payload: unknown): unknown {
    if (typeof payload !== 'string') {
      return payload;
    }

    try {
      return JSON.parse(payload) as unknown;
    } catch {
      return payload;
    }
  }

  private parseRedisUrl(redisUrl: string) {
    const url = new URL(redisUrl);
    if (url.protocol !== 'redis:' && url.protocol !== 'rediss:') {
      throw new Error('REDIS_URL must use redis:// or rediss://');
    }

    const database = url.pathname.slice(1);
    return {
      host: url.hostname,
      port: url.port ? Number(url.port) : 6379,
      username: url.username ? decodeURIComponent(url.username) : undefined,
      password: url.password ? decodeURIComponent(url.password) : undefined,
      db: database ? Number(database) : undefined,
      tls: url.protocol === 'rediss:' ? {} : undefined,
    };
  }
}
