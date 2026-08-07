/**
 * Sanitize a user-supplied filename for display only.
 * Never use the result as a storage object key.
 */
export function sanitizeFilename(filename: string): string {
  const base = filename.split(/[/\\]/).pop() ?? 'unnamed';
  const cleaned = base
    .replace(/[^\w.\- ()[\]]+/g, '_')
    .replace(/^\.+/, '')
    .slice(0, 255);

  return cleaned.length > 0 ? cleaned : 'unnamed';
}
