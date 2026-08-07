import { ulid } from 'ulid';

export function createId(prefix: string): string {
  return `${prefix}_${ulid()}`;
}

export function createScanId(): string {
  return createId('scan');
}

export function createFileId(): string {
  return createId('file');
}

export function createEventId(): string {
  return createId('evt');
}

export function createCorrelationId(): string {
  return createId('corr');
}

export function createTraceId(): string {
  return createId('trace');
}

/** Random quarantine object key — never use the original filename. */
export function createQuarantineObjectKey(): string {
  return `q/${ulid()}`;
}
