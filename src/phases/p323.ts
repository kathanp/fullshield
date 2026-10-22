/**
 * Phase 323. CORS origin abstract value.
 * Off unless FULLSHIELD_EXPERIMENTAL_CORSV2=1.
 * Regex search is local and fuel-capped. It does not send a preflight.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CORSV2';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export type CorsOrigin =
  | { kind: 'literal'; value: string }
  | { kind: 'literals'; values: readonly string[] }
  | { kind: 'reflect-request' }
  | { kind: 'regex'; source: string }
  | { kind: 'function'; identity: boolean }
  | { kind: 'null' };

export interface CorsOptions {
  file: string;
  line: number;
  origin: CorsOrigin;
  credentials: boolean;
  fuel?: number;
}

export interface CorsEvent {
  code: 271;
  file: string;
  detail: string;
}

export interface CorsFinding {
  ruleId: 'CONFIG-CORSV2-001';
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: 'low' | 'medium' | 'high';
  file: string;
  line: number;
  message: string;
  witness: string;
}

export interface CorsResult {
  findings: CorsFinding[];
  events: CorsEvent[];
}

function intendedHost(source: string): string | undefined {
  const stripped = source.replace(/^\^/, '').replace(/\$$/, '');
  const match = /([A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+)/.exec(stripped);
  const raw = match?.[1];
  if (raw === undefined) {
    return undefined;
  }
  return raw.replace(/\\./g, '.');
}

function boundaryHost(sample: string, host: string): boolean {
  const index = sample.indexOf(host);
  if (index < 0) {
    return false;
  }
  const before = index === 0 ? '' : (sample[index - 1] ?? '');
  const after = sample[index + host.length] ?? '';
  const beforeOk = before === '' || before === '.' || before === '/' || before === '@';
  const afterOk = after === '' || after === '.' || after === '/' || after === ':';
  return beforeOk && afterOk;
}

function row(file: string, line: number, severity: CorsFinding['severity'], confidence: CorsFinding['confidence'], message: string, witness: string): CorsFinding {
  return { ruleId: 'CONFIG-CORSV2-001', severity, confidence, file, line, message, witness };
}

export function corsFindings(options: CorsOptions): CorsResult {
  if (!enabled()) {
    return { findings: [], events: [] };
  }
  const { file, line, origin } = options;
  if (origin.kind === 'reflect-request' && options.credentials) {
    return { findings: [row(file, line, 'critical', 'high', 'CORS reflects the request origin with credentials.', 'reflect-request')], events: [] };
  }
  const literals = origin.kind === 'literal' ? [origin.value] : origin.kind === 'literals' ? origin.values : origin.kind === 'null' ? ['null'] : undefined;
  if (literals !== undefined) {
    if (literals.includes('null')) {
      return { findings: [row(file, line, 'high', 'high', 'CORS allows the null origin.', 'null')], events: [] };
    }
    return { findings: [], events: [] };
  }
  if (origin.kind === 'function') {
    if (origin.identity) {
      return { findings: [], events: [] };
    }
    return { findings: [row(file, line, 'low', 'low', 'CORS origin function is not the identity echo.', 'function')], events: [] };
  }
  if (origin.kind !== 'regex') {
    return { findings: [], events: [] };
  }
  if (/\\[1-9]/.test(origin.source)) {
    return {
      findings: [row(file, line, 'low', 'low', 'CORS regex is unknown to the automaton.', origin.source)],
      events: [],
    };
  }
  let compiled: RegExp;
  try {
    compiled = new RegExp(origin.source);
  } catch {
    return { findings: [row(file, line, 'low', 'low', 'CORS regex is unknown to the automaton.', origin.source)], events: [] };
  }
  const host = intendedHost(origin.source);
  if (host === undefined) {
    return { findings: [row(file, line, 'low', 'low', 'CORS regex is unknown to the automaton.', origin.source)], events: [] };
  }
  const candidates = [`not${host}`, `x${host}`, `${host}.attacker.example`, `https://${host}.not.example`];
  let left = options.fuel ?? 32;
  for (const candidate of candidates) {
    if (left <= 0) {
      return {
        findings: [row(file, line, 'low', 'low', 'CORS regex search exhausted its fuel.', 'fuel')],
        events: [{ code: 271, file, detail: 'cors regex fuel exhausted' }],
      };
    }
    left -= 1;
    if (compiled.test(candidate) && !boundaryHost(candidate, host)) {
      return {
        findings: [row(file, line, 'medium', 'medium', 'CORS regex accepts a string that is not a boundary match of the intended host.', candidate)],
        events: [],
      };
    }
  }
  return { findings: [], events: [] };
}
