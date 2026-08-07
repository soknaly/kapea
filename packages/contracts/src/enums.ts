import { z } from 'zod';

export const ScanStatus = {
  UPLOADING: 'UPLOADING',
  QUEUED: 'QUEUED',
  SCANNING: 'SCANNING',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED',
  EXPIRED: 'EXPIRED',
  DELETED: 'DELETED',
} as const;

export const ScanStatusSchema = z.enum([
  'UPLOADING',
  'QUEUED',
  'SCANNING',
  'COMPLETED',
  'FAILED',
  'EXPIRED',
  'DELETED',
]);

export type ScanStatus = z.infer<typeof ScanStatusSchema>;

export const Verdict = {
  CLEAN: 'CLEAN',
  SUSPICIOUS: 'SUSPICIOUS',
  MALICIOUS: 'MALICIOUS',
  UNKNOWN: 'UNKNOWN',
  SCAN_FAILED: 'SCAN_FAILED',
} as const;

export const VerdictSchema = z.enum([
  'CLEAN',
  'SUSPICIOUS',
  'MALICIOUS',
  'UNKNOWN',
  'SCAN_FAILED',
]);

export type Verdict = z.infer<typeof VerdictSchema>;

export const ScanStage = {
  QUEUED: 'QUEUED',
  DOWNLOAD: 'DOWNLOAD',
  HASH_VERIFY: 'HASH_VERIFY',
  FILE_TYPE: 'FILE_TYPE',
  CLAMAV_SCAN: 'CLAMAV_SCAN',
  YARA_SCAN: 'YARA_SCAN',
  ARCHIVE_INSPECT: 'ARCHIVE_INSPECT',
  FORMAT_ANALYZE: 'FORMAT_ANALYZE',
  INDICATOR_EXTRACT: 'INDICATOR_EXTRACT',
  RISK_SCORE: 'RISK_SCORE',
  COMPLETE: 'COMPLETE',
} as const;

export const ScanStageSchema = z.enum([
  'QUEUED',
  'DOWNLOAD',
  'HASH_VERIFY',
  'FILE_TYPE',
  'CLAMAV_SCAN',
  'YARA_SCAN',
  'ARCHIVE_INSPECT',
  'FORMAT_ANALYZE',
  'INDICATOR_EXTRACT',
  'RISK_SCORE',
  'COMPLETE',
]);

export type ScanStage = z.infer<typeof ScanStageSchema>;

export const FileSource = {
  WEB_API: 'WEB_API',
  TELEGRAM: 'TELEGRAM',
} as const;

export const FileSourceSchema = z.enum(['WEB_API', 'TELEGRAM']);

export type FileSource = z.infer<typeof FileSourceSchema>;
