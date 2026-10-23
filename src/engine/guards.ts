/** Phase 258. Dominating guards clear only the labels they make impossible. */

export const GUARD_FLAG = 'FULLSHIELD_EXPERIMENTAL_GUARDS';

export function guardsEnabled(): boolean {
  return process.env[GUARD_FLAG] === '1';
}

const SINK_META: Record<string, string> = {
  sqli: `'";\\`,
  nosqli: '$',
  cmdi: ';|&$`',
  path: '/\\.',
  xss: `<>"'`,
  ssrf: ':/@?',
  redirect: ':/@?',
  eval: '()',
  ssti: '{}',
  log: '\n\r',
};

export interface GuardHit {
  variable: string;
  clears: string[];
}

function classAdmits(classBody: string, label: string): boolean {
  const meta = SINK_META[label] ?? '';
  if (classBody.includes('.')) {return true;}
  for (const ch of meta) {
    if (classBody.includes(ch)) {return true;}
  }
  if (label === 'path' && (classBody.includes('/') || classBody.includes('\\') || classBody.includes('.'))) {return true;}
  return false;
}

/** Anchored class that excludes the sink metacharacters. Unanchored is not a guard. */
export function regexClears(pattern: string, label: string): boolean {
  const match = /^\/\^\[([^\]]+)\]\+\$\/[a-z]*$/.exec(pattern);
  if (match === null) {return false;}
  const body = match[1] ?? '';
  return !classAdmits(body, label);
}

function guardOn(line: string): { variable: string; pattern: string } | undefined {
  const allow = /if\s*\(\s*!\s*([A-Za-z0-9_]+)\.includes\(\s*([A-Za-z0-9_]+)\s*\)\s*\)/.exec(line);
  if (allow !== null) {
    const list = allow[1];
    const variable = allow[2];
    if (list !== undefined && variable !== undefined) {return { variable, pattern: `allowlist:${list}` };}
  }
  const eq = /if\s*\(\s*!\s*\(\s*([A-Za-z0-9_]+)\s*===\s*'[^']+'\s*\|\|\s*\1\s*===\s*'[^']+'\s*\)\s*\)/.exec(line);
  if (eq?.[1] !== undefined) {return { variable: eq[1], pattern: 'eq' };}
  const re = /if\s*\(\s*!\s*(\/[^/]+\/[a-z]*)\.test\(\s*([A-Za-z0-9_]+)\s*\)\s*\)/.exec(line);
  if (re?.[1] !== undefined && re[2] !== undefined) {return { variable: re[2], pattern: re[1] };}
  const prefix = /if\s*\(\s*!\s*path\.resolve\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\)\.startsWith\(\s*\1\s*\+\s*path\.sep\s*\)\s*\)/.exec(line);
  if (prefix?.[2] !== undefined) {return { variable: prefix[2], pattern: 'path-sep' };}
  const weak = /if\s*\(\s*!\s*path\.resolve\(\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\)\.startsWith\(\s*\1\s*\)\s*\)/.exec(line);
  if (weak !== null) {return undefined;}
  const typeGuard = /if\s*\(\s*typeof\s+([A-Za-z0-9_]+)\s*!==\s*'number'\s*\)/.exec(line);
  if (typeGuard?.[1] !== undefined) {return { variable: typeGuard[1], pattern: 'typeof-number' };}
  return undefined;
}

function clearsFor(source: string, pattern: string, label: string): boolean {
  if (pattern.startsWith('allowlist:')) {
    const list = pattern.slice('allowlist:'.length);
    if (!new RegExp(`(?:const|let|var)\\s+${list}\\s*=\\s*\\[`).test(source)) {return false;}
    return true;
  }
  if (pattern === 'eq' || pattern === 'typeof-number') {return true;}
  if (pattern === 'path-sep') {return label === 'path';}
  return regexClears(pattern, label);
}

/**
 * A guard dominates the sink when it sits at the function's top level and the
 * failing branch returns or throws before that sink. Nested guards do not.
 */
export function sinkStillReports(source: string, variable: string, label: string): boolean {
  if (!guardsEnabled()) {return false;}
  const lines = source.split('\n');
  let depth = 0;
  const cleared = new Set<string>();
  for (const line of lines) {
    const sink = new RegExp(`\\.(query|exec|eval|send|redirect)\\s*\\([^)]*\\b${variable}\\b`).test(line);
    if (sink && depth === 1) {return !cleared.has(`${variable}:${label}`);}
    const guard = guardOn(line);
    const failsClosed = /return|throw/.test(line);
    if (guard !== undefined && failsClosed && depth === 1 && clearsFor(source, guard.pattern, label)) {
      cleared.add(`${guard.variable}:${label}`);
    }
    depth += (line.match(/\{/g) ?? []).length;
    depth -= (line.match(/\}/g) ?? []).length;
  }
  return false;
}
