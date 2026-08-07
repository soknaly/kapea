import { Injectable } from '@nestjs/common';
import { createMetrics, type KAPEAMetrics } from './metrics';

@Injectable()
export class MetricsService {
  readonly metrics: KAPEAMetrics;

  constructor() {
    const serviceName = process.env.SERVICE_NAME || 'kapea';
    this.metrics = createMetrics(serviceName);
  }

  recordUpload(source: string): void {
    this.metrics.uploadsTotal.inc({ source });
  }

  recordScanQueued(): void {
    this.metrics.scansQueuedTotal.inc();
  }

  recordScanCompleted(verdict: string): void {
    this.metrics.scansCompletedTotal.inc({ verdict });
  }

  async render(): Promise<string> {
    return this.metrics.registry.metrics();
  }
}
