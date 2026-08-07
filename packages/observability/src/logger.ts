export type LogFields = Record<string, string | number | boolean | null | undefined>;

export function structuredLog(
  level: 'info' | 'warn' | 'error' | 'debug',
  message: string,
  fields: LogFields = {},
): void {
  const entry = {
    level,
    message,
    timestamp: new Date().toISOString(),
    ...fields,
  };

  const line = JSON.stringify(entry);

  switch (level) {
    case 'error':
      console.error(line);
      break;
    case 'warn':
      console.warn(line);
      break;
    case 'debug':
      console.debug(line);
      break;
    default:
      console.log(line);
  }
}
