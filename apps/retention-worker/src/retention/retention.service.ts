import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { SchedulerRegistry } from '@nestjs/schedule';
import { ConfigService } from '@nestjs/config';
import { createEventId } from '@kapea/common';
import { PrismaService } from '@kapea/database';
import { StorageService } from '@kapea/storage';

const RETENTION_MS: Record<string, number> = {
  CLEAN: 24 * 60 * 60 * 1000,
  SUSPICIOUS: 7 * 24 * 60 * 60 * 1000,
  MALICIOUS: 30 * 24 * 60 * 60 * 1000,
};

const UPLOADING_STUCK_MS = 60 * 60 * 1000;

@Injectable()
export class RetentionService implements OnModuleInit {
  private readonly logger = new Logger(RetentionService.name);
  private running = false;

  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly storage: StorageService,
    private readonly schedulerRegistry: SchedulerRegistry,
  ) {}

  onModuleInit(): void {
    const intervalMs = Number(
      this.config.get<string>('RETENTION_INTERVAL_MS', '300000'),
    );

    const interval = setInterval(() => {
      void this.runRetentionCycle();
    }, intervalMs);
    this.schedulerRegistry.addInterval('retention-cycle', interval);

    this.logger.log(`Retention worker scheduled every ${intervalMs}ms`);
  }

  async runRetentionCycle(): Promise<void> {
    if (this.running) {
      return;
    }

    this.running = true;
    try {
      this.logger.log('Starting retention cycle');
      const deleted = await this.deleteExpiredFiles();
      const stuck = await this.cleanupStuckUploads();
      this.logger.log(
        `Retention cycle complete: ${deleted} expired deletions, ${stuck} stuck uploads cleaned`,
      );
    } finally {
      this.running = false;
    }
  }

  private async deleteExpiredFiles(): Promise<number> {
    const now = new Date();
    let deletedCount = 0;

    const candidates = await this.prisma.scanJob.findMany({
      where: {
        status: { in: ['COMPLETED', 'FAILED'] },
        file: { deletedAt: null },
      },
      include: {
        file: true,
        result: true,
      },
      take: 500,
    });

    for (const job of candidates) {
      const expiresAt = this.resolveExpiresAt(job);
      if (expiresAt > now) {
        continue;
      }

      try {
        await this.deleteFileRecord(job.id, job.file, 'RETENTION_DELETE');
        deletedCount += 1;
      } catch (err) {
        this.logger.error(`Retention delete failed for scan ${job.id}`, err);
        await this.prisma.auditLog.create({
          data: {
            id: createEventId(),
            actorType: 'retention_worker',
            action: 'RETENTION_DELETE_FAILED',
            entityType: 'scan_job',
            entityId: job.id,
            metadataJson: {
              fileId: job.file.id,
              error: err instanceof Error ? err.message : 'unknown',
            },
          },
        });
      }
    }

    return deletedCount;
  }

  private resolveExpiresAt(job: {
    completedAt: Date | null;
    createdAt: Date;
    file: { expiresAt: Date | null };
    result: { verdict: string } | null;
  }): Date {
    if (job.file.expiresAt) {
      return job.file.expiresAt;
    }

    const base = job.completedAt ?? job.createdAt;
    const verdict = job.result?.verdict ?? 'CLEAN';
    const ms = RETENTION_MS[verdict] ?? RETENTION_MS.CLEAN;
    return new Date(base.getTime() + ms);
  }

  private async cleanupStuckUploads(): Promise<number> {
    const cutoff = new Date(Date.now() - UPLOADING_STUCK_MS);
    let cleaned = 0;

    const stuckJobs = await this.prisma.scanJob.findMany({
      where: {
        status: 'UPLOADING',
        createdAt: { lt: cutoff },
        file: { deletedAt: null },
      },
      include: { file: true },
      take: 100,
    });

    for (const job of stuckJobs) {
      try {
        await this.deleteFileRecord(job.id, job.file, 'UPLOADING_CLEANUP');
        cleaned += 1;
      } catch (err) {
        this.logger.error(`Stuck upload cleanup failed for scan ${job.id}`, err);
      }
    }

    return cleaned;
  }

  private async deleteFileRecord(
    scanId: string,
    file: {
      id: string;
      storageBucket: string;
      storageKey: string;
      deletedAt: Date | null;
    },
    auditAction: string,
  ): Promise<void> {
    if (!file.deletedAt) {
      try {
        await this.storage.deleteObject({
          bucket: file.storageBucket,
          key: file.storageKey,
        });
      } catch {
        // Continue — object may already be gone.
      }
    }

    const now = new Date();

    await this.prisma.$transaction(async (tx) => {
      await tx.file.update({
        where: { id: file.id },
        data: { deletedAt: now },
      });

      await tx.scanJob.update({
        where: { id: scanId },
        data: { status: 'DELETED' },
      });

      await tx.auditLog.create({
        data: {
          id: createEventId(),
          actorType: 'retention_worker',
          action: auditAction,
          entityType: 'scan_job',
          entityId: scanId,
          metadataJson: {
            fileId: file.id,
            storageKey: file.storageKey,
          },
        },
      });
    });
  }
}
