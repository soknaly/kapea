import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  createCorrelationId,
  createEventId,
  createId,
  createTraceId,
} from '@kapea/common';
import { EVENT_VERSION, type ScanStatus } from '@kapea/contracts';
import { PrismaService } from '@kapea/database';
import { QueueService } from '@kapea/messaging';
import { RedisService } from '@kapea/redis';
import { StorageService } from '@kapea/storage';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { basename, join } from 'node:path';
import { OverrideVerdictDto } from './dto/override-verdict.dto';
import { DeployYaraRuleDto } from './dto/yara-rule.dto';

const RETENTION_MS: Record<string, number> = {
  CLEAN: 24 * 60 * 60 * 1000,
  SUSPICIOUS: 7 * 24 * 60 * 60 * 1000,
  MALICIOUS: 30 * 24 * 60 * 60 * 1000,
};

interface ListScansQuery {
  status?: ScanStatus;
  limit?: number;
  cursor?: string;
}

interface ListAuditLogsQuery {
  limit?: number;
  cursor?: string;
}

@Injectable()
export class AdminService {
  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly storage: StorageService,
    private readonly queue: QueueService,
    private readonly redis: RedisService,
  ) {}

  async listScans(query: ListScansQuery) {
    const limit = Math.min(Math.max(query.limit ?? 20, 1), 100);
    const cursor = query.cursor ? this.decodeCursor(query.cursor) : null;

    const where: {
      status?: ScanStatus;
      OR?: Array<
        | { createdAt: { lt: Date } }
        | { createdAt: Date; id: { lt: string } }
      >;
    } = {};
    if (query.status) {
      where.status = query.status;
    }
    if (cursor) {
      where.OR = [
        { createdAt: { lt: cursor.createdAt } },
        { createdAt: cursor.createdAt, id: { lt: cursor.id } },
      ];
    }

    const rows = await this.prisma.scanJob.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit + 1,
      include: {
        file: {
          select: {
            id: true,
            sanitizedFilename: true,
            sizeBytes: true,
            source: true,
            sha256: true,
          },
        },
        result: {
          select: {
            verdict: true,
            automatedVerdict: true,
            riskScore: true,
          },
        },
      },
    });

    const hasMore = rows.length > limit;
    const items = hasMore ? rows.slice(0, limit) : rows;
    const last = items[items.length - 1];

    return {
      items: items.map((job) => ({
        scanId: job.id,
        fileId: job.fileId,
        status: job.status,
        progress: job.progress,
        attemptCount: job.attemptCount,
        filename: job.file.sanitizedFilename,
        sizeBytes: job.file.sizeBytes.toString(),
        source: job.file.source,
        sha256: job.file.sha256,
        verdict: job.result?.verdict ?? null,
        automatedVerdict: job.result?.automatedVerdict ?? null,
        riskScore: job.result?.riskScore ?? null,
        createdAt: job.createdAt.toISOString(),
        completedAt: job.completedAt?.toISOString() ?? null,
      })),
      nextCursor:
        hasMore && last
          ? this.encodeCursor(last.createdAt, last.id)
          : null,
    };
  }

  async getScanReport(scanId: string) {
    const scanJob = await this.prisma.scanJob.findUnique({
      where: { id: scanId },
      include: {
        file: true,
        result: {
          include: {
            findings: true,
            indicators: true,
          },
        },
      },
    });

    if (!scanJob) {
      throw new NotFoundException(`Scan ${scanId} not found`);
    }

    const { file, result, ...job } = scanJob;

    return {
      scan: {
        id: job.id,
        fileId: job.fileId,
        status: job.status,
        progress: job.progress,
        currentStage: job.currentStage,
        attemptCount: job.attemptCount,
        messageEventId: job.messageEventId,
        startedAt: job.startedAt?.toISOString() ?? null,
        completedAt: job.completedAt?.toISOString() ?? null,
        failedAt: job.failedAt?.toISOString() ?? null,
        failureCode: job.failureCode,
        failureMessage: job.failureMessage,
        workerId: job.workerId,
        createdAt: job.createdAt.toISOString(),
        updatedAt: job.updatedAt.toISOString(),
      },
      file: {
        id: file.id,
        originalFilename: file.originalFilename,
        sanitizedFilename: file.sanitizedFilename,
        storageBucket: file.storageBucket,
        storageKey: file.storageKey,
        sizeBytes: file.sizeBytes.toString(),
        claimedMimeType: file.claimedMimeType,
        detectedMimeType: file.detectedMimeType,
        extension: file.extension,
        sha256: file.sha256,
        sha1: file.sha1,
        md5: file.md5,
        source: file.source,
        sourceReference: file.sourceReference,
        uploadedBy: file.uploadedBy,
        createdAt: file.createdAt.toISOString(),
        expiresAt: file.expiresAt?.toISOString() ?? null,
        deletedAt: file.deletedAt?.toISOString() ?? null,
      },
      result: result
        ? {
            id: result.id,
            verdict: result.verdict,
            automatedVerdict: result.automatedVerdict,
            riskScore: result.riskScore,
            summary: result.summary,
            scanComplete: result.scanComplete,
            clamavVersion: result.clamavVersion,
            clamavSignatureVersion: result.clamavSignatureVersion,
            yaraRuleVersion: result.yaraRuleVersion,
            scannerVersion: result.scannerVersion,
            eventVersion: result.eventVersion,
            createdAt: result.createdAt.toISOString(),
            threatLabels: result.threatLabelsJson ?? null,
            findings: result.findings,
            indicators: result.indicators,
          }
        : null,
    };
  }

  async retryScan(scanId: string, ipAddress?: string) {
    const scanJob = await this.prisma.scanJob.findUnique({
      where: { id: scanId },
      include: { file: true },
    });

    if (!scanJob) {
      throw new NotFoundException(`Scan ${scanId} not found`);
    }

    if (scanJob.status === 'DELETED') {
      throw new BadRequestException('Cannot retry a deleted scan');
    }

    const { file } = scanJob;
    const correlationId = createCorrelationId();
    const traceId = createTraceId();
    const eventId = createEventId();

    await this.prisma.$transaction(async (tx) => {
      const existing = await tx.scanResult.findUnique({
        where: { scanJobId: scanId },
      });
      if (existing) {
        await tx.scanFinding.deleteMany({
          where: { scanResultId: existing.id },
        });
        await tx.extractedIndicator.deleteMany({
          where: { scanResultId: existing.id },
        });
        await tx.scanResult.delete({ where: { id: existing.id } });
      }

      await tx.scanJob.update({
        where: { id: scanId },
        data: {
          status: 'QUEUED',
          progress: 0,
          currentStage: null,
          attemptCount: { increment: 1 },
          failureCode: null,
          failureMessage: null,
          failedAt: null,
          completedAt: null,
          workerId: null,
          messageEventId: null,
        },
      });
    });

    await this.queue.enqueueScanRequested({
      eventId,
      eventType: 'scan.requested',
      eventVersion: EVENT_VERSION,
      occurredAt: new Date().toISOString(),
      correlationId,
      scanId,
      fileId: file.id,
      traceId,
      storage: {
        bucket: file.storageBucket,
        objectKey: file.storageKey,
      },
      expectedSizeBytes: Number(file.sizeBytes),
      expectedSha256: file.sha256,
      originalFilename: file.sanitizedFilename,
      claimedMimeType: file.claimedMimeType,
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

    await this.prisma.auditLog.create({
      data: {
        id: createEventId(),
        actorType: 'admin',
        action: 'SCAN_RETRY',
        entityType: 'scan_job',
        entityId: scanId,
        metadataJson: { eventId, attemptCount: scanJob.attemptCount + 1 },
        ipAddress: ipAddress ?? null,
      },
    });

    return {
      scanId,
      status: 'QUEUED',
      attemptCount: scanJob.attemptCount + 1,
      message: 'Scan re-queued for processing.',
    };
  }

  async overrideVerdict(
    scanId: string,
    dto: OverrideVerdictDto,
    ipAddress?: string,
  ) {
    const scanJob = await this.prisma.scanJob.findUnique({
      where: { id: scanId },
      include: { result: true },
    });

    if (!scanJob) {
      throw new NotFoundException(`Scan ${scanId} not found`);
    }

    if (!scanJob.result) {
      throw new BadRequestException('Scan has no result to override');
    }

    const previousVerdict = scanJob.result.verdict;

    await this.prisma.$transaction(async (tx) => {
      await tx.scanResult.update({
        where: { id: scanJob.result!.id },
        data: { verdict: dto.verdict },
      });

      await tx.auditLog.create({
        data: {
          id: createEventId(),
          actorType: 'admin',
          action: 'VERDICT_OVERRIDE',
          entityType: 'scan_job',
          entityId: scanId,
          metadataJson: {
            previousVerdict,
            newVerdict: dto.verdict,
            automatedVerdict: scanJob.result!.automatedVerdict,
            reason: dto.reason,
          },
          ipAddress: ipAddress ?? null,
        },
      });
    });

    return {
      scanId,
      verdict: dto.verdict,
      automatedVerdict: scanJob.result.automatedVerdict,
      message: 'Displayed verdict updated. Automated verdict remains unchanged.',
    };
  }

  async deleteScanFile(scanId: string, ipAddress?: string) {
    const scanJob = await this.prisma.scanJob.findUnique({
      where: { id: scanId },
      include: { file: true },
    });

    if (!scanJob) {
      throw new NotFoundException(`Scan ${scanId} not found`);
    }

    if (scanJob.status === 'DELETED') {
      return {
        scanId,
        status: 'DELETED',
        message: 'File was already deleted.',
      };
    }

    const { file } = scanJob;

    if (!file.deletedAt) {
      try {
        await this.storage.deleteObject({
          bucket: file.storageBucket,
          key: file.storageKey,
        });
      } catch {
        // Force delete — continue even if object is missing.
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
          actorType: 'admin',
          action: 'FILE_FORCE_DELETE',
          entityType: 'scan_job',
          entityId: scanId,
          metadataJson: {
            fileId: file.id,
            storageKey: file.storageKey,
          },
          ipAddress: ipAddress ?? null,
        },
      });
    });

    return {
      scanId,
      status: 'DELETED',
      message: 'File force-deleted from quarantine.',
    };
  }

  async listScanners() {
    const scanners = await this.prisma.scannerDefinition.findMany({
      orderBy: { engine: 'asc' },
    });

    return {
      items: scanners.map((s) => ({
        id: s.id,
        engine: s.engine,
        version: s.version,
        status: s.status,
        installedAt: s.installedAt.toISOString(),
        updatedAt: s.updatedAt.toISOString(),
        metadata: s.metadataJson,
      })),
    };
  }

  async patchScanner(engine: string, status: 'enabled' | 'disabled') {
    const scanner = await this.prisma.scannerDefinition.findUnique({
      where: { engine },
    });

    if (!scanner) {
      throw new NotFoundException(`Scanner engine ${engine} not found`);
    }

    const updated = await this.prisma.scannerDefinition.update({
      where: { engine },
      data: { status },
    });

    await this.prisma.auditLog.create({
      data: {
        id: createEventId(),
        actorType: 'admin',
        action: 'SCANNER_STATUS_CHANGE',
        entityType: 'scanner_definition',
        entityId: updated.id,
        metadataJson: { engine, previousStatus: scanner.status, status },
      },
    });

    return {
      engine: updated.engine,
      status: updated.status,
      version: updated.version,
    };
  }

  private getYaraRulesPath(): string {
    return this.config.get<string>(
      'YARA_RULES_PATH',
      join(process.cwd(), '../../infrastructure/yara/rules'),
    );
  }

  async listYaraRules() {
    const rulesPath = this.getYaraRulesPath();

    let entries: string[];
    try {
      entries = await fs.readdir(rulesPath);
    } catch {
      return { path: rulesPath, items: [] };
    }

    const items = await Promise.all(
      entries
        .filter((name) => name.endsWith('.yar') || name.endsWith('.yara'))
        .map(async (name) => {
          const filePath = join(rulesPath, name);
          const stat = await fs.stat(filePath);
          const content = await fs.readFile(filePath, 'utf8');
          const sha256 = createHash('sha256').update(content).digest('hex');
          const ruleNames = [...content.matchAll(/^\s*rule\s+(\w+)/gm)].map(
            (m) => m[1],
          );

          return {
            filename: name,
            path: filePath,
            sizeBytes: stat.size,
            modifiedAt: stat.mtime.toISOString(),
            sha256,
            ruleNames,
          };
        }),
    );

    return { path: rulesPath, items };
  }

  validateYaraRule(ruleText: string) {
    const errors: string[] = [];

    if (!/\brule\s+\w+/i.test(ruleText)) {
      errors.push('Missing rule declaration (expected "rule RuleName")');
    }

    if (!/\bcondition\s*:/i.test(ruleText)) {
      errors.push('Missing condition block');
    }

    if (ruleText.includes('\0')) {
      errors.push('Rule text contains null bytes');
    }

    const openBraces = (ruleText.match(/{/g) ?? []).length;
    const closeBraces = (ruleText.match(/}/g) ?? []).length;
    if (openBraces !== closeBraces) {
      errors.push('Mismatched braces');
    }

    return {
      valid: errors.length === 0,
      errors,
      ruleNames: [...ruleText.matchAll(/^\s*rule\s+(\w+)/gm)].map((m) => m[1]),
    };
  }

  async deployYaraRule(dto: DeployYaraRuleDto, ipAddress?: string) {
    const validation = this.validateYaraRule(dto.ruleText);
    if (!validation.valid) {
      throw new BadRequestException({
        message: 'YARA rule validation failed',
        errors: validation.errors,
      });
    }

    const rulesPath = this.getYaraRulesPath();
    await fs.mkdir(rulesPath, { recursive: true });

    const safeName = basename(dto.filename).replace(/[^a-zA-Z0-9._-]/g, '_');
    if (!safeName.endsWith('.yar') && !safeName.endsWith('.yara')) {
      throw new BadRequestException('Filename must end with .yar or .yara');
    }

    const filePath = join(rulesPath, safeName);
    await fs.writeFile(filePath, dto.ruleText, 'utf8');

    const version =
      dto.version ?? createHash('sha256').update(dto.ruleText).digest('hex').slice(0, 12);

    await this.prisma.scannerDefinition.upsert({
      where: { engine: 'yara' },
      create: {
        id: createId('scanner'),
        engine: 'yara',
        version,
        status: 'enabled',
        installedAt: new Date(),
        metadataJson: {
          rulesPath,
          deployedFile: safeName,
          ruleNames: validation.ruleNames,
        },
      },
      update: {
        version,
        metadataJson: {
          rulesPath,
          deployedFile: safeName,
          ruleNames: validation.ruleNames,
          deployedAt: new Date().toISOString(),
        },
      },
    });

    await this.prisma.auditLog.create({
      data: {
        id: createEventId(),
        actorType: 'admin',
        action: 'YARA_RULE_DEPLOY',
        entityType: 'yara_rule',
        entityId: safeName,
        metadataJson: { filename: safeName, version, ruleNames: validation.ruleNames },
        ipAddress: ipAddress ?? null,
      },
    });

    return {
      filename: safeName,
      path: filePath,
      version,
      ruleNames: validation.ruleNames,
      message: 'YARA rule deployed.',
    };
  }

  async listAuditLogs(query: ListAuditLogsQuery) {
    const limit = Math.min(Math.max(query.limit ?? 50, 1), 200);
    const cursor = query.cursor ? this.decodeCursor(query.cursor) : null;

    const where: {
      OR?: Array<
        | { createdAt: { lt: Date } }
        | { createdAt: Date; id: { lt: string } }
      >;
    } = cursor
      ? {
          OR: [
            { createdAt: { lt: cursor.createdAt } },
            { createdAt: cursor.createdAt, id: { lt: cursor.id } },
          ],
        }
      : {};

    const rows = await this.prisma.auditLog.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit + 1,
    });

    const hasMore = rows.length > limit;
    const items = hasMore ? rows.slice(0, limit) : rows;
    const last = items[items.length - 1];

    return {
      items: items.map((log) => ({
        id: log.id,
        actorType: log.actorType,
        actorId: log.actorId,
        action: log.action,
        entityType: log.entityType,
        entityId: log.entityId,
        metadata: log.metadataJson,
        ipAddress: log.ipAddress,
        createdAt: log.createdAt.toISOString(),
      })),
      nextCursor:
        hasMore && last
          ? this.encodeCursor(last.createdAt, last.id)
          : null,
    };
  }

  async getAdminHealth() {
    const checks: Record<string, 'ok' | 'error'> = {
      postgres: 'error',
      redis: 'error',
      queue: 'error',
      storage: 'error',
    };

    try {
      await this.prisma.$queryRaw`SELECT 1`;
      checks.postgres = 'ok';
    } catch {
      checks.postgres = 'error';
    }

    try {
      const pong = await this.redis.ping();
      checks.redis = pong === 'PONG' ? 'ok' : 'error';
    } catch {
      checks.redis = 'error';
    }

    checks.queue = (await this.queue.isConnected()) ? 'ok' : 'error';

    try {
      const bucket = this.storage.getDefaultBucket();
      await this.storage.ensureBucket(bucket);
      checks.storage = 'ok';
    } catch {
      checks.storage = 'error';
    }

    const [
      scanCounts,
      scanners,
      recentFailures,
      yaraRules,
    ] = await Promise.all([
      this.prisma.scanJob.groupBy({
        by: ['status'],
        _count: { id: true },
      }),
      this.prisma.scannerDefinition.findMany(),
      this.prisma.scanJob.count({
        where: {
          status: 'FAILED',
          failedAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
        },
      }),
      this.listYaraRules(),
    ]);

    const statusCounts = Object.fromEntries(
      scanCounts.map((row) => [row.status, row._count.id]),
    );

    const allOk = Object.values(checks).every((s) => s === 'ok');

    return {
      status: allOk ? 'ok' : 'degraded',
      checks,
      scans: statusCounts,
      scanners: scanners.map((s) => ({
        engine: s.engine,
        version: s.version,
        status: s.status,
      })),
      failuresLast24h: recentFailures,
      yaraRules: {
        path: yaraRules.path,
        ruleFileCount: yaraRules.items.length,
      },
      retentionDefaults: {
        CLEAN: '24h',
        SUSPICIOUS: '7d',
        MALICIOUS: '30d',
      },
    };
  }

  /** Compute expiresAt from verdict when not explicitly set. */
  static computeExpiresAt(
    verdict: string | null | undefined,
    completedAt: Date,
  ): Date {
    const ms = RETENTION_MS[verdict ?? ''] ?? RETENTION_MS.CLEAN;
    return new Date(completedAt.getTime() + ms);
  }

  private encodeCursor(createdAt: Date, id: string): string {
    return Buffer.from(JSON.stringify({ createdAt: createdAt.toISOString(), id })).toString(
      'base64url',
    );
  }

  private decodeCursor(cursor: string): { createdAt: Date; id: string } {
    try {
      const parsed = JSON.parse(
        Buffer.from(cursor, 'base64url').toString('utf8'),
      ) as { createdAt: string; id: string };
      return { createdAt: new Date(parsed.createdAt), id: parsed.id };
    } catch {
      throw new BadRequestException('Invalid cursor');
    }
  }
}
