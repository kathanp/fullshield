/**
 * Phase 368. SBOM field completeness.
 * Off unless FULLSHIELD_EXPERIMENTAL_SBOMFIELDS=1.
 * Counts holes. Does not print a grade or a score.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SBOMFIELDS';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export const NOT_A_GRADE = 'These counts are not a grade.';

export interface SbomComponentInput {
  name?: string;
  version?: string;
  purl?: string;
  /** Lock integrity, when present. */
  integrity?: string | null;
}

export interface SbomHole {
  field: 'name' | 'version' | 'purl' | 'hash';
  component: string;
}

export interface SbomFieldReport {
  header: string;
  counts: { name: number; version: number; purl: number; hash: number };
  rows: SbomHole[];
  components: Array<{ name: string; version: string; purl: string; hash: string | null }>;
}

function purlFor(name: string, version: string): string {
  const scoped = name.startsWith('@');
  const encoded = scoped ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
  return `pkg:npm/${encoded}@${version}`;
}

function blank(value: string | undefined): boolean {
  return value === undefined || value === '';
}

function componentPurl(component: SbomComponentInput, name: string, version: string): string {
  if (component.purl !== undefined) {
    return component.purl;
  }
  if (name !== '' && version !== '') {
    return purlFor(name, version);
  }
  return '';
}

function storedHash(hash: string | null): string | null {
  if (hash === '') {
    return null;
  }
  return hash;
}

function recordComponent(component: SbomComponentInput, rows: SbomHole[]): SbomFieldReport['components'][number] {
  const name = component.name ?? '';
  const version = component.version ?? '';
  const label = name === '' ? '<unnamed>' : name;
  if (blank(component.name)) {
    rows.push({ field: 'name', component: label });
  }
  if (blank(component.version)) {
    rows.push({ field: 'version', component: label });
  }
  const purl = componentPurl(component, name, version);
  if (purl === '') {
    rows.push({ field: 'purl', component: label });
  }
  const hash = component.integrity ?? null;
  if (hash === null || hash === '') {
    rows.push({ field: 'hash', component: label });
  }
  return { name, version, purl, hash: storedHash(hash) };
}

function holeCounts(rows: readonly SbomHole[]): SbomFieldReport['counts'] {
  return {
    name: rows.filter((row) => row.field === 'name').length,
    version: rows.filter((row) => row.field === 'version').length,
    purl: rows.filter((row) => row.field === 'purl').length,
    hash: rows.filter((row) => row.field === 'hash').length,
  };
}

export function sbomFieldReport(components: readonly SbomComponentInput[]): SbomFieldReport | null {
  if (!enabled()) {
    return null;
  }
  const rows: SbomHole[] = [];
  const filled: SbomFieldReport['components'] = [];
  for (const component of components) {
    filled.push(recordComponent(component, rows));
  }
  return { header: NOT_A_GRADE, counts: holeCounts(rows), rows, components: filled };
}
