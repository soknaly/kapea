import {
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { createEventId } from '@kapea/common';
import { PrismaService } from '@kapea/database';
import { StorageService } from '@kapea/storage';

export interface ScanStatusResponse {
  scanId: string;
  status: string;
  progress: number;
  currentStage: string | null;
}

export interface ScanFindingResponse {
  engine: string;
  code: string;
  severity: number;
  confidence: number;
  message: string;
}

export interface ScanResultResponse {
  scanId: string;
  filename: string;
  detectedFileType: string | null;
  sha256: string | null;
  verdict: string;
  automatedVerdict: string;
  riskScore: number;
  scanComplete: boolean;
  summary: string;
  findings: ScanFindingResponse[];
  threatLabels: unknown | null;
  completedAt: string | null;
}

@Injectable()
export class ScansService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly storage: StorageService,
  ) {}

  async getScanStatus(scanId: string): Promise<ScanStatusResponse> {
    const scanJob = await this.prisma.scanJob.findUnique({
      where: { id: scanId },
    });

    if (!scanJob) {
      throw new NotFoundException(`Scan ${scanId} not found`);
    }

    return {
      scanId: scanJob.id,
      status: scanJob.status,
      progress: scanJob.progress,
      currentStage: scanJob.currentStage,
    };
  }

  async getScanResult(scanId: string): Promise<ScanResultResponse> {
    const scanJob = await this.prisma.scanJob.findUnique({
      where: { id: scanId },
      include: {
        file: true,
        result: {
          include: {
            findings: true,
          },
        },
      },
    });

    if (!scanJob) {
      throw new NotFoundException(`Scan ${scanId} not found`);
    }

    if (!scanJob.result) {
      throw new NotFoundException(`Scan result for ${scanId} is not available yet`);
    }

    const { file, result } = scanJob;

    return {
      scanId: scanJob.id,
      filename: file.sanitizedFilename,
      detectedFileType: file.detectedMimeType,
      sha256: file.sha256,
      verdict: result.verdict,
      automatedVerdict: result.automatedVerdict,
      riskScore: result.riskScore,
      scanComplete: result.scanComplete,
      summary: result.summary,
      findings: result.findings.map((finding) => ({
        engine: finding.engine,
        code: finding.code,
        severity: finding.severity,
        confidence: finding.confidence,
        message: finding.message,
      })),
      threatLabels: result.threatLabelsJson ?? null,
      completedAt: scanJob.completedAt?.toISOString() ?? null,
    };
  }

  async deleteScanFile(
    scanId: string,
    ipAddress?: string,
  ): Promise<{ scanId: string; status: string; message: string }> {
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
      await this.storage.deleteObject({
        bucket: file.storageBucket,
        key: file.storageKey,
      });
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
          actorType: 'api_client',
          action: 'file.deleted',
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
      message: 'File deleted successfully.',
    };
  }
}
