/**
 * Phase 447. Versioned scan JSON.
 * Off unless FULLSHIELD_EXPERIMENTAL_JSONSCHEMA=1.
 * Flag off: default JSON keeps the stable keys and does not gain schemaVersion.
 * Removing a stable required key fails the semver check. This phase does not bump the package.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_JSONSCHEMA';

export const STABLE_REQUIRED = ['findings', 'summary', 'metadata'] as const;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export const SCAN_SCHEMA: Record<string, unknown> = {
  $id: 'docs/scan-result.schema.json',
  type: 'object',
  required: [...STABLE_REQUIRED],
  properties: {
    schemaVersion: { const: 1 },
    findings: { type: 'array' },
    summary: { type: 'object' },
    metadata: { type: 'object' },
    experimental: { type: 'object' },
  },
};

export interface ScanDocument {
  findings: unknown[];
  summary: Record<string, unknown>;
  metadata: Record<string, unknown>;
  experimental?: Record<string, unknown>;
}

export function emitScanJson(doc: ScanDocument): { json: string; keys: string[] } {
  const stable: Record<string, unknown> = {
    findings: doc.findings,
    summary: doc.summary,
    metadata: doc.metadata,
  };
  if (!enabled()) {
    return { json: JSON.stringify(stable), keys: Object.keys(stable) };
  }
  const withExperimental = { ...stable, experimental: doc.experimental ?? {} };
  return { json: JSON.stringify(withExperimental), keys: Object.keys(withExperimental) };
}

export function validateScanDocument(doc: unknown): string[] {
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return ['scan document must be an object'];
  }
  const record = doc as Record<string, unknown>;
  const errors: string[] = [];
  for (const key of STABLE_REQUIRED) {
    if (record[key] === undefined) {
      errors.push(`missing ${key}`);
    }
  }
  return errors;
}

export function diffStableRequired(previous: readonly string[], next: readonly string[]): string[] {
  const kept = new Set(next);
  return previous.filter((key) => !kept.has(key));
}

export function assertSemverCompatible(previous: readonly string[], next: readonly string[]): void {
  const removed = diffStableRequired(previous, next);
  if (removed.length > 0) {
    throw new Error(`stable required key removed: ${removed.join(',')}`);
  }
}
