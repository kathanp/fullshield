export class SpdxInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SpdxInputError';
  }
}

const MILLIS = /\.\d{3}Z$/;

/** SPDX created time. `--sbom-timestamp` wins, then `SOURCE_DATE_EPOCH`, then now. */
export function spdxCreated(explicit?: string): string {
  if (explicit !== undefined && explicit.trim().length > 0) {return formatSpdxDate(explicit.trim());}
  const epoch = process.env.SOURCE_DATE_EPOCH;
  if (epoch !== undefined && epoch.trim().length > 0) {return formatSpdxDate(epoch.trim());}
  return formatSpdxDate(new Date().toISOString());
}

function formatSpdxDate(value: string): string {
  const ms = /^\d+$/.test(value) ? Number(value) * 1000 : Date.parse(value);
  if (!Number.isFinite(ms)) {throw new SpdxInputError(`invalid SBOM timestamp "${value}"`);}
  return new Date(ms).toISOString().replace(MILLIS, 'Z');
}
