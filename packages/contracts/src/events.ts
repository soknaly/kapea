import { z } from 'zod';
import { ScanFindingSchema } from './findings';
import { ScanStageSchema, VerdictSchema } from './enums';
import { ThreatLabelsSchema } from './threat-labels';

export const EventEnvelopeSchema = z.object({
  eventId: z.string().min(1),
  eventType: z.string().min(1),
  eventVersion: z.number().int().positive(),
  occurredAt: z.string().datetime(),
  correlationId: z.string().min(1),
  scanId: z.string().min(1),
  fileId: z.string().min(1),
  traceId: z.string().min(1),
});

export type EventEnvelope = z.infer<typeof EventEnvelopeSchema>;

export const ScanLimitsSchema = z.object({
  maxExtractedBytes: z.number().int().positive(),
  maxFiles: z.number().int().positive(),
  maxDepth: z.number().int().positive(),
  timeoutSeconds: z.number().int().positive(),
});

export type ScanLimits = z.infer<typeof ScanLimitsSchema>;

export const StorageRefSchema = z.object({
  bucket: z.string().min(1),
  objectKey: z.string().min(1),
});

export type StorageRef = z.infer<typeof StorageRefSchema>;

/** Subject: scan.requested.v1 */
export const ScanRequestedEventSchema = EventEnvelopeSchema.extend({
  eventType: z.literal('scan.requested'),
  eventVersion: z.literal(1),
  storage: StorageRefSchema,
  expectedSizeBytes: z.number().int().nonnegative(),
  expectedSha256: z.string().min(1).nullable(),
  originalFilename: z.string().min(1),
  claimedMimeType: z.string().nullable(),
  limits: ScanLimitsSchema,
});

export type ScanRequestedEvent = z.infer<typeof ScanRequestedEventSchema>;

/** Subject: scan.progress.v1 */
export const ScanProgressEventSchema = EventEnvelopeSchema.extend({
  eventType: z.literal('scan.progress'),
  eventVersion: z.literal(1),
  status: z.literal('SCANNING'),
  progress: z.number().int().min(0).max(100),
  currentStage: ScanStageSchema,
  workerId: z.string().min(1),
  message: z.string().optional(),
});

export type ScanProgressEvent = z.infer<typeof ScanProgressEventSchema>;

export const FileHashesSchema = z.object({
  sha256: z.string().min(1),
  sha1: z.string().min(1),
  md5: z.string().min(1),
});

export type FileHashes = z.infer<typeof FileHashesSchema>;

export const ExtractedIndicatorSchema = z.object({
  indicatorType: z.string().min(1),
  indicatorValue: z.string().min(1),
  sourcePath: z.string().nullable().optional(),
});

export type ExtractedIndicator = z.infer<typeof ExtractedIndicatorSchema>;

/** Subject: scan.completed.v1 */
export const ScanCompletedEventSchema = EventEnvelopeSchema.extend({
  eventType: z.literal('scan.completed'),
  eventVersion: z.literal(1),
  scanComplete: z.boolean(),
  detectedFileType: z.string().nullable(),
  hashes: FileHashesSchema,
  findings: z.array(ScanFindingSchema),
  riskScore: z.number().int().min(0).max(100),
  automatedVerdict: VerdictSchema,
  summary: z.string(),
  scannerVersions: z.record(z.string()),
  timing: z.object({
    startedAt: z.string().datetime(),
    completedAt: z.string().datetime(),
    durationMs: z.number().int().nonnegative(),
  }),
  workerId: z.string().min(1),
  extractedIndicators: z.array(ExtractedIndicatorSchema).optional(),
  threatLabels: ThreatLabelsSchema.optional(),
});

export type ScanCompletedEvent = z.infer<typeof ScanCompletedEventSchema>;

/** Subject: scan.failed.v1 */
export const ScanFailedEventSchema = EventEnvelopeSchema.extend({
  eventType: z.literal('scan.failed'),
  eventVersion: z.literal(1),
  errorCode: z.string().min(1),
  errorMessage: z.string().min(1),
  workerId: z.string().min(1).optional(),
  retryable: z.boolean().default(false),
});

export type ScanFailedEvent = z.infer<typeof ScanFailedEventSchema>;

/** Logical event names carried in BullMQ job data / progress / return values. */
export const QUEUE_EVENT_TYPES = {
  SCAN_REQUESTED: 'scan.requested',
  SCAN_PROGRESS: 'scan.progress',
  SCAN_COMPLETED: 'scan.completed',
  SCAN_FAILED: 'scan.failed',
} as const;

export const EVENT_VERSION = 1 as const;
