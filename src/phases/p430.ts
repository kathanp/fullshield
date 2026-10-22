/**
 * Phase 430. SARIF taxonomies.
 * Off unless FULLSHIELD_EXPERIMENTAL_SARIFTAX=1.
 * Flag off: the SARIF text is returned without a taxonomies block.
 * CWE ids come from rule front matter. The title is never a mapping source.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SARIFTAX';

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

export interface RuleMapping {
  id: string;
  cwe: string[];
  /** Required when cwe is the token none. */
  reason?: string;
}

export interface MappedRule extends RuleMapping {
  title: string;
}

function strip(value: string): string {
  return value.trim().replace(/^["']|["']$/g, '');
}

export function parseFrontMatter(markdown: string): RuleMapping | null {
  const fence = /^---\n([\s\S]*?)\n---/.exec(markdown);
  const body = fence?.[1];
  if (body === undefined) {
    return null;
  }
  const id = /^id:\s*(\S+)/m.exec(body)?.[1];
  if (id === undefined) {
    return null;
  }
  const none = /^cwe:\s*none\s*$/m.exec(body);
  if (none !== null) {
    const reason = /^cweReason:\s*(.+)$/m.exec(body)?.[1];
    return { id, cwe: ['none'], ...(reason !== undefined ? { reason: reason.trim() } : {}) };
  }
  const list = body.split('\n').filter((line) => /^\s+-\s+/.test(line)).map((line) => strip(line.replace(/^\s+-\s+/, '')));
  return { id, cwe: list };
}

export function assertMapping(rule: RuleMapping | null): string[] {
  if (rule === null || rule.cwe.length === 0) {
    return ['missing CWE mapping'];
  }
  if (rule.cwe.length === 1 && rule.cwe[0] === 'none' && (rule.reason === undefined || rule.reason.length === 0)) {
    return ['cwe: none requires a reason'];
  }
  return [];
}

/** Refuses a mapper that only has a title. */
export function mapCwe(input: { title: string; frontMatter?: RuleMapping }): string[] {
  if (input.frontMatter === undefined) {
    throw new FsError('refusing to map CWE from the title alone');
  }
  const errors = assertMapping(input.frontMatter);
  if (errors.length > 0) {
    throw new FsError(errors.join('; '));
  }
  return input.frontMatter.cwe;
}

export function renderTaxonomy(base: string, rules: readonly MappedRule[]): string {
  if (!enabled()) {
    return base;
  }
  const parsed = JSON.parse(base) as unknown;
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return base;
  }
  const doc = parsed as Record<string, unknown>;
  const taxa = rules.flatMap((rule) => rule.cwe.filter((id) => id !== 'none').map((id) => ({ ruleId: rule.id, cwe: id })));
  return JSON.stringify({ ...doc, taxonomies: [{ name: 'CWE', rules: taxa }] });
}
