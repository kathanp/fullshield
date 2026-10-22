/**
 * Phase 444. CODEOWNERS on findings.
 * Off unless FULLSHIELD_EXPERIMENTAL_OWNERS=1.
 * Flag off: findings have no owner field.
 * Last matching pattern wins. A syntax error is FS-E and no owner is guessed.
 * This module does not call a forge API.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_OWNERS';

export class FsError extends Error {
  readonly code = 'FS-E' as const;
  constructor(message: string) {
    super(message);
    this.name = 'FsError';
  }
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface OwnedFinding {
  ruleId: string;
  file: string;
  line: number;
  severity: string;
  owner?: string;
}

interface Pattern {
  regex: RegExp;
  owner: string;
  anywhere: boolean;
}

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function compile(pattern: string): Pattern {
  const anchored = pattern.startsWith('/');
  const body = anchored ? pattern.slice(1) : pattern;
  const regex = new RegExp(`^${body.split('*').map(escapeRegex).join('[^/]*')}$`);
  return { regex, owner: '', anywhere: !pattern.includes('/') };
}

export function parseCodeowners(text: string): Pattern[] {
  const patterns: Pattern[] = [];
  const lines = text.split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }
    const parts = line.split(/\s+/);
    const pattern = parts[0];
    const owner = parts[1];
    if (pattern === undefined || owner === undefined) {
      throw new FsError('FS-E CODEOWNERS syntax error');
    }
    const compiled = compile(pattern);
    compiled.owner = owner;
    patterns.push(compiled);
  }
  return patterns;
}

function matches(pattern: Pattern, file: string): boolean {
  const normalized = file.replace(/\\/g, '/').replace(/^\.\//, '');
  if (pattern.regex.test(normalized)) {
    return true;
  }
  if (!pattern.anywhere) {
    return false;
  }
  const base = normalized.split('/').pop() ?? normalized;
  return pattern.regex.test(base);
}

export function ownerFor(file: string, patterns: readonly Pattern[]): string {
  let owner = 'unowned';
  for (const pattern of patterns) {
    if (matches(pattern, file)) {
      owner = pattern.owner;
    }
  }
  return owner;
}

export function attachOwners(findings: readonly OwnedFinding[], codeowners: string): OwnedFinding[] {
  if (!enabled()) {
    return findings.map((finding) => ({ ...finding }));
  }
  const patterns = parseCodeowners(codeowners);
  return findings.map((finding) => ({ ...finding, owner: ownerFor(finding.file, patterns) }));
}
