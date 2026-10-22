/**
 * Phase 352. Pull-request dependency flags.
 * Off unless FULLSHIELD_EXPERIMENTAL_DEPRFLAGS=1.
 * Tokens are a closed set. A score key is rejected. Flag off fails with FS-E352.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_DEPRFLAGS';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export class DepFlagsError extends Error {
  readonly code = 'FS-E352';
  constructor(message: string) {
    super(`FS-E352 ${message}`);
    this.name = 'DepFlagsError';
  }
}

export const RISK_TOKENS = ['advisory-critical', 'install-script', 'new-direct', 'non-registry-host'] as const;
export type RiskToken = (typeof RISK_TOKENS)[number];

export interface DepFacts {
  installScript?: boolean;
  advisoryCritical?: boolean;
  resolvedHost?: string;
}

export interface RiskRow {
  name: string;
  riskFlags: RiskToken[];
}

const DEP_LINE = /^[+-]\s*"([^"]+)":\s*"([^"]+)"/;

export function assertNoScore(value: unknown): void {
  if (value !== null && typeof value === 'object' && 'score' in value) {
    throw new DepFlagsError('schema rejects score');
  }
}

export function dependencyFlags(readDiff: () => string, facts: ReadonlyMap<string, DepFacts>): RiskRow[] {
  if (!enabled()) {
    throw new DepFlagsError('FULLSHIELD_EXPERIMENTAL_DEPRFLAGS');
  }
  const diff = readDiff();
  const removed = new Map<string, string>();
  const added = new Map<string, string>();
  for (const line of diff.split('\n')) {
    const match = DEP_LINE.exec(line);
    if (match?.[1] === undefined || match[2] === undefined) {
      continue;
    }
    if (line.startsWith('-') && !line.startsWith('---')) {
      removed.set(match[1], match[2]);
    }
    if (line.startsWith('+') && !line.startsWith('+++')) {
      added.set(match[1], match[2]);
    }
  }
  const rows: RiskRow[] = [];
  for (const [name, version] of added) {
    if (removed.get(name) === version) {
      continue;
    }
    const fact = facts.get(name);
    const tokens = new Set<RiskToken>();
    if (!removed.has(name)) {
      tokens.add('new-direct');
    }
    if (fact?.installScript === true) {
      tokens.add('install-script');
    }
    if (fact?.advisoryCritical === true) {
      tokens.add('advisory-critical');
    }
    if (fact?.resolvedHost !== undefined && fact.resolvedHost !== 'registry.npmjs.org') {
      tokens.add('non-registry-host');
    }
    if (tokens.size === 0) {
      continue;
    }
    rows.push({ name, riskFlags: [...tokens].sort((a, b) => a.localeCompare(b)) });
  }
  assertNoScore({ rows });
  return rows;
}
