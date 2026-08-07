import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { createEventId, createId } from '@kapea/common';
import {
  ScanCompletedEvent,
  ScanCompletedEventSchema,
  ScanFailedEvent,
  ScanFailedEventSchema,
  ScanProgressEvent,
  ScanProgressEventSchema,
} from '@kapea/contracts';
import { PrismaService } from '@kapea/database';
import { QueueService } from '@kapea/messaging';
import { MetricsService } from '@kapea/observability';

@Injectable()
export class ResultConsumerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ResultConsumerService.name);
  private readonly unsubscribe: Array<() => void> = [];

  constructor(
    private readonly queue: QueueService,
    private readonly prisma: PrismaService,
    private readonly metrics: MetricsService,
  ) {}

  onModuleInit(): void {
    this.unsubscribe.push(
      this.queue.onScanProgress((event) => this.handleProgress(event)),
      this.queue.onScanCompleted((event) => this.handleCompleted(event)),
      this.queue.onScanFailed((event) => this.handleFailed(event)),
    );

    this.logger.log(
      'Listening for BullMQ scan progress, completed, and failed events',
    );
  }

  onModuleDestroy(): void {
    for (const unsubscribe of this.unsubscribe) {
      unsubscribe();
    }
  }

  async handleProgress(raw: ScanProgressEvent): Promise<void> {
    const event = ScanProgressEventSchema.parse(raw);

    const scanJob = await this.prisma.scanJob.findUnique({
      where: { id: event.scanId },
    });

    if (!scanJob) {
      throw new Error(`Scan job ${event.scanId} not found`);
    }

    if (scanJob.messageEventId === event.eventId) {
      return;
    }

    if (scanJob.status === 'COMPLETED' || scanJob.status === 'FAILED') {
      return;
    }

    await this.prisma.scanJob.update({
      where: { id: event.scanId },
      data: {
        status: 'SCANNING',
        progress: event.progress,
        currentStage: event.currentStage,
        workerId: event.workerId,
        messageEventId: event.eventId,
        startedAt: scanJob.startedAt ?? new Date(event.occurredAt),
      },
    });
  }

  async handleCompleted(raw: ScanCompletedEvent): Promise<void> {
    const event = ScanCompletedEventSchema.parse(raw);

    const existingResult = await this.prisma.scanResult.findUnique({
      where: { scanJobId: event.scanId },
    });

    if (existingResult) {
      // Idempotent create — but still reconcile job status (retries can leave
      // the job at SCANNING after a duplicate completed event).
      await this.reconcileJobAfterCompleted(event);
      return;
    }

    const scanJob = await this.prisma.scanJob.findUnique({
      where: { id: event.scanId },
    });

    if (!scanJob) {
      throw new Error(`Scan job ${event.scanId} not found`);
    }

    const resultId = createId('result');
    const versions = event.scannerVersions;

    await this.prisma.$transaction(async (tx) => {
      await tx.scanResult.create({
        data: {
          id: resultId,
          scanJobId: event.scanId,
          verdict: event.automatedVerdict,
          automatedVerdict: event.automatedVerdict,
          riskScore: event.riskScore,
          summary: event.summary,
          scanComplete: event.scanComplete,
          clamavVersion: versions.clamav ?? versions.clamav_version ?? null,
          clamavSignatureVersion:
            versions.clamav_signature ??
            versions.clamav_signature_version ??
            null,
          yaraRuleVersion: versions.yara ?? versions.yara_rules ?? null,
          scannerVersion: versions.worker ?? versions.scanner ?? null,
          eventVersion: event.eventVersion,
          threatLabelsJson: event.threatLabels ?? undefined,
          findings: {
            create: event.findings.map((finding) => ({
              id: createId('finding'),
              engine: finding.engine,
              code: finding.code,
              category: finding.category,
              severity: finding.severity,
              confidence: finding.confidence,
              message: finding.message,
              technicalDetailsJson:
                finding.technicalDetails === undefined
                  ? undefined
                  : (finding.technicalDetails as object),
              pathInsideArchive: finding.pathInsideArchive ?? null,
            })),
          },
          indicators: {
            create: (event.extractedIndicators ?? []).map((indicator) => ({
              id: createId('indicator'),
              indicatorType: indicator.indicatorType,
              indicatorValue: indicator.indicatorValue,
              sourcePath: indicator.sourcePath ?? null,
            })),
          },
        },
      });

      const failed = event.automatedVerdict === 'SCAN_FAILED';
      await tx.scanJob.update({
        where: { id: event.scanId },
        data: {
          status: failed ? 'FAILED' : 'COMPLETED',
          completedAt: failed
            ? null
            : new Date(event.timing.completedAt),
          failedAt: failed ? new Date(event.timing.completedAt) : null,
          failureCode: failed ? 'SCAN_FAILED' : null,
          failureMessage: failed ? event.summary : null,
          progress: 100,
          currentStage: 'COMPLETE',
          workerId: event.workerId,
          messageEventId: event.eventId,
          startedAt: scanJob.startedAt ?? new Date(event.timing.startedAt),
        },
      });

      await tx.file.update({
        where: { id: event.fileId },
        data: {
          detectedMimeType: event.detectedFileType,
          sha256: event.hashes.sha256,
          sha1: event.hashes.sha1,
          md5: event.hashes.md5,
        },
      });

      await tx.auditLog.create({
        data: {
          id: createEventId(),
          actorType: 'scan_worker',
          actorId: event.workerId,
          action: 'SCAN_COMPLETED',
          entityType: 'scan_job',
          entityId: event.scanId,
          metadataJson: {
            eventId: event.eventId,
            verdict: event.automatedVerdict,
            riskScore: event.riskScore,
            findingCount: event.findings.length,
          },
        },
      });
    });

    this.metrics.recordScanCompleted(event.automatedVerdict);
  }

  private async reconcileJobAfterCompleted(
    event: ScanCompletedEvent,
  ): Promise<void> {
    const failed = event.automatedVerdict === 'SCAN_FAILED';
    await this.prisma.scanJob.updateMany({
      where: {
        id: event.scanId,
        status: { notIn: ['COMPLETED', 'FAILED', 'DELETED'] },
      },
      data: {
        status: failed ? 'FAILED' : 'COMPLETED',
        completedAt: failed ? null : new Date(event.timing.completedAt),
        failedAt: failed ? new Date(event.timing.completedAt) : null,
        failureCode: failed ? 'SCAN_FAILED' : null,
        failureMessage: failed ? event.summary : null,
        progress: 100,
        currentStage: 'COMPLETE',
        workerId: event.workerId,
        messageEventId: event.eventId,
      },
    });
  }

  async handleFailed(raw: ScanFailedEvent): Promise<void> {
    const event = ScanFailedEventSchema.parse(raw);

    const scanJob = await this.prisma.scanJob.findUnique({
      where: { id: event.scanId },
      include: { result: true },
    });

    if (!scanJob) {
      throw new Error(`Scan job ${event.scanId} not found`);
    }

    if (scanJob.result) {
      return;
    }

    if (scanJob.messageEventId === event.eventId) {
      return;
    }

    if (scanJob.status === 'COMPLETED') {
      return;
    }

    await this.prisma.$transaction(async (tx) => {
      await tx.scanJob.update({
        where: { id: event.scanId },
        data: {
          status: 'FAILED',
          failedAt: new Date(event.occurredAt),
          failureCode: event.errorCode,
          failureMessage: event.errorMessage,
          workerId: event.workerId ?? scanJob.workerId,
          messageEventId: event.eventId,
        },
      });

      await tx.auditLog.create({
        data: {
          id: createEventId(),
          actorType: 'scan_worker',
          actorId: event.workerId ?? null,
          action: 'SCAN_FAILED',
          entityType: 'scan_job',
          entityId: event.scanId,
          metadataJson: {
            eventId: event.eventId,
            errorCode: event.errorCode,
            retryable: event.retryable,
          },
        },
      });
    });

    this.metrics.recordScanCompleted('SCAN_FAILED');
  }
}
