/**
 * Phase 361. Manifest field mismatch.
 * Off unless FULLSHIELD_EXPERIMENTAL_MANIFESTCONF=1.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_MANIFESTCONF';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface ManifestFields {
  name?: string;
  version?: string;
  scripts?: Readonly<Record<string, string>>;
  dependencies?: Readonly<Record<string, string>>;
}

export interface ManifestCompareInput {
  packageName: string;
  lock: ManifestFields;
  packument: ManifestFields | null;
  /** Null when the tarball cache is absent. Those fields are then skipped. */
  tarball: ManifestFields | null;
  /** Phase 169 already reported name or version for this package. */
  phase169ReportedNameOrVersion: boolean;
}

export interface ManifestMismatch {
  ruleId: 'DEPS-MANIFEST-MISMATCH-001';
  severity: 'high' | 'medium' | 'low';
  packageName: string;
  field: string;
  left: string;
  right: string;
  message: string;
}

const ABSENT = '<absent>';

/** Canonical numeric form so `1.0` and `1.0.0` compare equal. */
export function canonicalDependency(spec: string): string {
  const match = /^([\^~>=<]*v?)(\d+)\.(\d+)(?:\.(\d+))?([\s\S]*)$/.exec(spec.trim());
  if (match === null) {
    return spec.trim();
  }
  const prefix = match[1] ?? '';
  const major = match[2] ?? '0';
  const minor = match[3] ?? '0';
  const patch = match[4] ?? '0';
  const rest = match[5] ?? '';
  return `${prefix}${major}.${minor}.${patch}${rest}`;
}

function sources(input: ManifestCompareInput): ManifestFields[] {
  const rows: ManifestFields[] = [input.lock];
  if (input.packument !== null) {
    rows.push(input.packument);
  }
  if (input.tarball !== null) {
    rows.push(input.tarball);
  }
  return rows;
}

function row(
  input: ManifestCompareInput,
  severity: ManifestMismatch['severity'],
  field: string,
  left: string,
  right: string,
): ManifestMismatch {
  return {
    ruleId: 'DEPS-MANIFEST-MISMATCH-001',
    severity,
    packageName: input.packageName,
    field,
    left,
    right,
    message: `${field} differs (${left} versus ${right})`,
  };
}

function differ(input: ManifestCompareInput, field: string, values: string[]): ManifestMismatch | null {
  const unique = [...new Set(values)];
  const left = unique[0];
  const right = unique[1];
  if (left === undefined || right === undefined) {
    return null;
  }
  const severity = field === 'name' || field === 'version' ? 'high' : field.startsWith('scripts.') ? 'medium' : 'low';
  return row(input, severity, field, left, right);
}

export function manifestMismatches(input: ManifestCompareInput): ManifestMismatch[] {
  if (!enabled()) {
    return [];
  }
  const sides = sources(input);
  if (input.tarball === null && input.packument === null) {
    return [];
  }
  const findings: ManifestMismatch[] = [];
  if (!input.phase169ReportedNameOrVersion) {
    for (const field of ['name', 'version'] as const) {
      const values: string[] = [];
      for (const side of sides) {
        const value = side[field];
        if (value !== undefined) {
          values.push(value);
        }
      }
      const hit = differ(input, field, values);
      if (hit !== null) {
        findings.push(hit);
      }
    }
  }
  const scriptSides = sides.filter((side) => side.scripts !== undefined);
  const depSides = sides.filter((side) => side.dependencies !== undefined);
  const scriptKeys = new Set<string>();
  const depKeys = new Set<string>();
  for (const side of scriptSides) {
    for (const key of Object.keys(side.scripts ?? {})) {
      scriptKeys.add(key);
    }
  }
  for (const side of depSides) {
    for (const key of Object.keys(side.dependencies ?? {})) {
      depKeys.add(key);
    }
  }
  for (const key of scriptKeys) {
    const values = scriptSides.map((side) => side.scripts?.[key] ?? ABSENT);
    const hit = differ(input, `scripts.${key}`, values);
    if (hit !== null) {
      findings.push(hit);
    }
  }
  for (const key of depKeys) {
    const values = depSides.map((side) => canonicalDependency(side.dependencies?.[key] ?? ABSENT));
    const hit = differ(input, `dependencies.${key}`, values);
    if (hit !== null) {
      findings.push(hit);
    }
  }
  return findings;
}
