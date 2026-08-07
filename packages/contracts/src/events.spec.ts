import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  ScanCompletedEventSchema,
  ScanRequestedEventSchema,
  Verdict,
} from './index';

describe('event contracts', () => {
  it('accepts a valid scan.requested event', () => {
    const event = ScanRequestedEventSchema.parse({
      eventId: 'evt_01',
      eventType: 'scan.requested',
      eventVersion: 1,
      occurredAt: '2026-08-05T10:00:00.000Z',
      correlationId: 'corr_01',
      scanId: 'scan_01',
      fileId: 'file_01',
      traceId: 'trace_01',
      storage: { bucket: 'quarantine', objectKey: 'q/abc' },
      expectedSizeBytes: 12,
      expectedSha256: 'abc',
      originalFilename: 'hello.txt',
      claimedMimeType: 'text/plain',
      limits: {
        maxExtractedBytes: 1000,
        maxFiles: 10,
        maxDepth: 2,
        timeoutSeconds: 60,
      },
    });
    assert.equal(event.eventType, 'scan.requested');
  });

  it('accepts completed events with indicators', () => {
    const event = ScanCompletedEventSchema.parse({
      eventId: 'evt_02',
      eventType: 'scan.completed',
      eventVersion: 1,
      occurredAt: '2026-08-05T10:01:00.000Z',
      correlationId: 'corr_01',
      scanId: 'scan_01',
      fileId: 'file_01',
      traceId: 'trace_01',
      scanComplete: true,
      detectedFileType: 'text/plain',
      hashes: {
        sha256: 'a'.repeat(64),
        sha1: 'b'.repeat(40),
        md5: 'c'.repeat(32),
      },
      findings: [],
      riskScore: 0,
      automatedVerdict: Verdict.CLEAN,
      summary: 'No threats detected.',
      scannerVersions: { worker: '0.1.0' },
      timing: {
        startedAt: '2026-08-05T10:00:00.000Z',
        completedAt: '2026-08-05T10:01:00.000Z',
        durationMs: 1000,
      },
      workerId: 'worker_1',
      extractedIndicators: [
        {
          indicatorType: 'url',
          indicatorValue: 'https://example.com',
          sourcePath: null,
        },
      ],
    });
    assert.equal(event.extractedIndicators?.length, 1);
  });
});
