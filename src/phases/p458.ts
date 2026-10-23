/**
 * Phase 458. Vercel and Netlify config.
 * Off unless FULLSHIELD_EXPERIMENTAL_EDGECFG=1.
 * Flag off: the baseline finding list is returned unchanged.
 * Does not call the hosting API.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_EDGECFG';
export const EDGE_REDIRECT = 'CONFIG-EDGE-REDIRECT-001';
export const EDGE_HEADER = 'CONFIG-EDGE-HEADER-001';
export const EDGE_PUBLIC = 'CONFIG-EDGE-PUBLICENV-001';

const CATALOG = ['X-Content-Type-Options', 'Referrer-Policy'];
const SECRET = /\bAKIA[0-9A-Z]{16}\b/;

function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface SecretFormat {
  id: string;
  pattern: RegExp;
  publicByDesign: boolean;
}

export interface PhaseFinding {
  ruleId: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  file: string;
  line: number;
  message: string;
  snippet?: string;
}

const DEFAULT_FORMATS: readonly SecretFormat[] = [{ id: 'aws-access-key', pattern: SECRET, publicByDesign: false }];

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function queryRedirect(destination: string): boolean {
  if (destination.startsWith('/') && !destination.includes('?') && !destination.includes(':')) {
    return false;
  }
  return destination.includes('?') || destination.includes(':') || destination.includes('query');
}

function headerNames(value: unknown): string[] {
  const names: string[] = [];
  const record = asRecord(value);
  if (record !== null) {
    names.push(...Object.keys(record));
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const row = asRecord(item);
      if (typeof row?.key === 'string') {
        names.push(row.key);
      }
      if (typeof row?.name === 'string') {
        names.push(row.name);
      }
    }
  }
  return names;
}

function publicEnv(key: string, value: string, formats: readonly SecretFormat[]): PhaseFinding | null {
  if (!key.startsWith('NEXT_PUBLIC_') && !key.startsWith('VITE_')) {
    return null;
  }
  const matched = formats.find((format) => format.pattern.test(value));
  if (matched === undefined || matched.publicByDesign) {
    return null;
  }
  return { ruleId: EDGE_PUBLIC, severity: 'high', file: '', line: 1, message: `public env ${key}`, snippet: '****' };
}

export function scanEdge(file: string, text: string, formats: readonly SecretFormat[] = DEFAULT_FORMATS, baseline: readonly PhaseFinding[] = []): PhaseFinding[] {
  if (!enabled()) {
    return [...baseline];
  }
  const findings: PhaseFinding[] = [];
  let headers: string[] = [];
  if (file.endsWith('.json')) {
    const doc = asRecord(JSON.parse(text) as unknown);
    const redirects = Array.isArray(doc?.redirects) ? doc.redirects : [];
    for (const item of redirects) {
      const destination = asRecord(item)?.destination;
      if (typeof destination === 'string' && queryRedirect(destination)) {
        findings.push({ ruleId: EDGE_REDIRECT, severity: 'high', file, line: 1, message: 'redirect target taken from a request parameter' });
      }
    }
    headers = headerNames(doc?.headers);
    const env = asRecord(doc?.env);
    if (env !== null) {
      for (const [key, value] of Object.entries(env)) {
        if (typeof value === 'string') {
          const hit = publicEnv(key, value, formats);
          if (hit !== null) {
            findings.push({ ...hit, file });
          }
        }
      }
    }
  } else {
    for (const line of text.split(/\r?\n/)) {
      const header = /^\s{2,}([A-Za-z0-9-]+)\s*[:=]\s*(.*)$/.exec(line);
      if (header?.[1] !== undefined) {
        headers.push(header[1]);
      }
      const redirect = /(?:to|destination)\s*=\s*"([^"]+)"/.exec(line);
      if (redirect?.[1] !== undefined && queryRedirect(redirect[1])) {
        findings.push({ ruleId: EDGE_REDIRECT, severity: 'high', file, line: 1, message: 'redirect target taken from a request parameter' });
      }
      const env = /\b(NEXT_PUBLIC_[A-Z0-9_]+|VITE_[A-Z0-9_]+)\s*=\s*"?([^"\s]+)/.exec(line);
      if (env?.[1] !== undefined && env[2] !== undefined) {
        const hit = publicEnv(env[1], env[2], formats);
        if (hit !== null) {
          findings.push({ ...hit, file });
        }
      }
    }
  }
  for (const name of CATALOG) {
    if (!headers.some((header) => header.toLowerCase() === name.toLowerCase())) {
      findings.push({ ruleId: EDGE_HEADER, severity: 'info', file, line: 1, message: `missing ${name}` });
    }
  }
  return [...baseline, ...findings];
}
