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

const RISK_TOKENS = ['advisory-critical', 'install-script', 'new-direct', 'non-registry-host'] as const;
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

interface DepSides {
  removed: Map<string, string>;
  added: Map<string, string>;
}

function recordLine(line: string, sides: DepSides): void {
  const match = DEP_LINE.exec(line);
  if (match?.[1] === undefined || match[2] === undefined) {
    return;
  }
  if (line.startsWith('-') && !line.startsWith('---')) {
    sides.removed.set(match[1], match[2]);
  }
  if (line.startsWith('+') && !line.startsWith('+++')) {
    sides.added.set(match[1], match[2]);
  }
}

function collectDiff(diff: string): DepSides {
  const sides: DepSides = { removed: new Map(), added: new Map() };
  for (const line of diff.split('\n')) {
    recordLine(line, sides);
  }
  return sides;
}

function addFactTokens(tokens: Set<RiskToken>, fact: DepFacts | undefined): void {
  if (fact?.installScript === true) {
    tokens.add('install-script');
  }
  if (fact?.advisoryCritical === true) {
    tokens.add('advisory-critical');
  }
  if (fact?.resolvedHost !== undefined && fact.resolvedHost !== 'registry.npmjs.org') {
    tokens.add('non-registry-host');
  }
}

function riskFlags(name: string, removed: ReadonlyMap<string, string>, fact: DepFacts | undefined): RiskToken[] {
  const tokens = new Set<RiskToken>();
  if (!removed.has(name)) {
    tokens.add('new-direct');
  }
  addFactTokens(tokens, fact);
  return [...tokens].sort((left, right) => left.localeCompare(right));
}

function riskRows(sides: DepSides, facts: ReadonlyMap<string, DepFacts>): RiskRow[] {
  const rows: RiskRow[] = [];
  for (const [name, version] of sides.added) {
    if (sides.removed.get(name) === version) {
      continue;
    }
    const flags = riskFlags(name, sides.removed, facts.get(name));
    if (flags.length === 0) {
      continue;
    }
    rows.push({ name, riskFlags: flags });
  }
  return rows;
}

export function dependencyFlags(readDiff: () => string, facts: ReadonlyMap<string, DepFacts>): RiskRow[] {
  if (!enabled()) {
    throw new DepFlagsError('FULLSHIELD_EXPERIMENTAL_DEPRFLAGS');
  }
  const rows = riskRows(collectDiff(readDiff()), facts);
  assertNoScore({ rows });
  return rows;
}
