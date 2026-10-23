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

function row(input: Pick<CorsFinding, 'file' | 'line' | 'severity' | 'confidence' | 'message' | 'witness'>): CorsFinding {
  return { ruleId: 'CONFIG-CORSV2-001', severity: input.severity, confidence: input.confidence, file: input.file, line: input.line, message: input.message, witness: input.witness };
}

function one(options: CorsOptions, severity: CorsFinding['severity'], confidence: CorsFinding['confidence'], message: string, witness: string): CorsResult {
  return { findings: [row({ file: options.file, line: options.line, severity, confidence, message, witness })], events: [] };
}

function literalValues(origin: CorsOrigin): readonly string[] | undefined {
  if (origin.kind === 'literal') {
    return [origin.value];
  }
  if (origin.kind === 'literals') {
    return origin.values;
  }
  if (origin.kind === 'null') {
    return ['null'];
  }
  return undefined;
}

function earlyFinding(options: CorsOptions): CorsResult | undefined {
  const origin = options.origin;
  if (origin.kind === 'reflect-request' && options.credentials) {
    return one(options, 'critical', 'high', 'CORS reflects the request origin with credentials.', 'reflect-request');
  }
  const literals = literalValues(origin);
  if (literals !== undefined) {
    if (literals.includes('null')) {
      return one(options, 'high', 'high', 'CORS allows the null origin.', 'null');
    }
    return { findings: [], events: [] };
  }
  if (origin.kind !== 'function') {
    return undefined;
  }
  if (origin.identity) {
    return { findings: [], events: [] };
  }
  return one(options, 'low', 'low', 'CORS origin function is not the identity echo.', 'function');
}

function unknownRegex(options: CorsOptions, source: string): CorsResult {
  return one(options, 'low', 'low', 'CORS regex is unknown to the automaton.', source);
}

function regexCandidates(host: string): string[] {
  return [`not${host}`, `x${host}`, `${host}.attacker.example`, `https://${host}.not.example`];
}

function compileRegex(source: string): RegExp | undefined {
  try {
    return new RegExp(source);
  } catch {
    return undefined;
  }
}

function searchRegex(compiled: RegExp, host: string, options: CorsOptions): CorsResult {
  let left = options.fuel ?? 32;
  for (const candidate of regexCandidates(host)) {
    if (left <= 0) {
      return {
        findings: [row({ file: options.file, line: options.line, severity: 'low', confidence: 'low', message: 'CORS regex search exhausted its fuel.', witness: 'fuel' })],
        events: [{ code: 271, file: options.file, detail: 'cors regex fuel exhausted' }],
      };
    }
    left -= 1;
    if (compiled.test(candidate) && !boundaryHost(candidate, host)) {
      return one(options, 'medium', 'medium', 'CORS regex accepts a string that is not a boundary match of the intended host.', candidate);
    }
  }
  return { findings: [], events: [] };
}

function regexFinding(options: CorsOptions): CorsResult {
  const origin = options.origin;
  if (origin.kind !== 'regex') {
    return { findings: [], events: [] };
  }
  if (/\\[1-9]/.test(origin.source)) {
    return unknownRegex(options, origin.source);
  }
  const compiled = compileRegex(origin.source);
  if (compiled === undefined) {
    return unknownRegex(options, origin.source);
  }
  const host = intendedHost(origin.source);
  if (host === undefined) {
    return unknownRegex(options, origin.source);
  }
  return searchRegex(compiled, host, options);
}

export function corsFindings(options: CorsOptions): CorsResult {
  if (!enabled()) {
    return { findings: [], events: [] };
  }
  const early = earlyFinding(options);
  if (early !== undefined) {
    return early;
  }
  return regexFinding(options);
}
