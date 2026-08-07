import { Counter, Registry, collectDefaultMetrics } from 'prom-client';

export interface KAPEAMetrics {
  registry: Registry;
  uploadsTotal: Counter<'source'>;
  scansQueuedTotal: Counter;
  scansCompletedTotal: Counter<'verdict'>;
}

export function createMetrics(serviceName = 'kapea'): KAPEAMetrics {
  const registry = new Registry();
  registry.setDefaultLabels({ service: serviceName });

  collectDefaultMetrics({ register: registry });

  const uploadsTotal = new Counter({
    name: 'kapea_uploads_total',
    help: 'Total file uploads accepted into quarantine',
    labelNames: ['source'] as const,
    registers: [registry],
  });

  const scansQueuedTotal = new Counter({
    name: 'kapea_scans_queued_total',
    help: 'Total scan jobs queued via BullMQ',
    registers: [registry],
  });

  const scansCompletedTotal = new Counter({
    name: 'kapea_scans_completed_total',
    help: 'Total scans completed (from result consumer perspective)',
    labelNames: ['verdict'] as const,
    registers: [registry],
  });

  return {
    registry,
    uploadsTotal,
    scansQueuedTotal,
    scansCompletedTotal,
  };
}

export async function renderMetrics(registry: Registry): Promise<string> {
  return registry.metrics();
}
