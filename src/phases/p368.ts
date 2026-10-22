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

export function sbomFieldReport(components: readonly SbomComponentInput[]): SbomFieldReport | null {
  if (!enabled()) {
    return null;
  }
  const rows: SbomHole[] = [];
  const filled: SbomFieldReport['components'] = [];
  for (const component of components) {
    const name = component.name ?? '';
    const version = component.version ?? '';
    const label = name === '' ? '<unnamed>' : name;
    if (component.name === undefined || component.name === '') {
      rows.push({ field: 'name', component: label });
    }
    if (component.version === undefined || component.version === '') {
      rows.push({ field: 'version', component: label });
    }
    const purl = component.purl ?? (name !== '' && version !== '' ? purlFor(name, version) : '');
    if (purl === '') {
      rows.push({ field: 'purl', component: label });
    }
    const hash = component.integrity ?? null;
    if (hash === null || hash === '') {
      rows.push({ field: 'hash', component: label });
    }
    filled.push({ name, version, purl, hash: hash === '' ? null : hash });
  }
  return {
    header: NOT_A_GRADE,
    counts: {
      name: rows.filter((row) => row.field === 'name').length,
      version: rows.filter((row) => row.field === 'version').length,
      purl: rows.filter((row) => row.field === 'purl').length,
      hash: rows.filter((row) => row.field === 'hash').length,
    },
    rows,
    components: filled,
  };
}
