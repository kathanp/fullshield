import type { GuardEvent, GuardOptions } from '../inspect.js';

export const DLP_FLAG = 'FULLSHIELD_EXPERIMENTAL_DLP';
export const DLP_MAX_BYTES = 64 * 1024;
export const DLP_GENERIC = { error: 'internal error' } as const;

export type DlpMode = 'monitor' | 'mask' | 'block';

export interface DlpHit {
  ruleId: string;
  sample: string;
}

export interface DlpInspectResult {
  action: 'allow' | 'mask' | 'block' | 'skip';
  body: unknown;
  hits: DlpHit[];
  skippedOverCap: boolean;
}

export interface DlpInspector {
  inspect(body: unknown, ctx: { path: string; ip?: string; contentType?: string }): DlpInspectResult;
  readonly skippedOverCap: number;
}

/** Same regexes as the secrets module rules — runtime must not import the scanner. */
const SECRET_RES: readonly RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bsk-ant-[A-Za-z0-9_-]{16,}\b|\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----/g,
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s'"@/:]+:[^\s'"@]+@/g,
];

const STACK_RE =
  /(?:Error|Exception|TypeError|ReferenceError|SyntaxError|RangeError)[^\n]{0,240}(?:\n|\r\n|\\n)[ \t]*at[ \t]+\S+[^\n]{0,320}(?:\n|\r\n|\\n)[ \t]*at[ \t]+/g;

const INTERNAL_IP_RE =
  /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b/g;

const HOST_TLDS = ['.internal', '.corp', '.lan', '.local'] as const;

const BULK_EMAILS = 5;
const PII_LEARN = 2;
const REDACT = '[REDACTED]';
const EMPTY_HITS: DlpHit[] = [];

export function isDlpEnabled(): boolean {
  return process.env[DLP_FLAG] === '1';
}

function allMatches(re: RegExp, text: string): RegExpExecArray[] {
  re.lastIndex = 0;
  return [...text.matchAll(re)] as RegExpExecArray[];
}

function maskSample(value: string): string {
  if (value.length <= 4) return '****';
  return `${value.slice(0, 4)}****`.slice(0, 40);
}

function luhnOk(digits: string): boolean {
  if (digits.length < 13 || digits.length > 19) return false;
  const first = digits.charCodeAt(0) - 48;
  if (first < 3 || first > 6) return false;
  if (digits.split('').every((c) => c === digits[0])) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

interface Span {
  start: number;
  end: number;
  ruleId: string;
  text: string;
}

const SECRET_MARKERS = [
  'AKIA',
  'sk_',
  'ghp_',
  'gho_',
  'ghu_',
  'ghs_',
  'ghr_',
  'xox',
  'AIza',
  'sk-',
  'BEGIN ',
  'postgres',
  'mysql',
  'mariadb',
  'mongodb',
  'redis',
  'amqp',
] as const;

function hasAny(text: string, markers: readonly string[]): boolean {
  for (const m of markers) {
    if (text.includes(m)) return true;
  }
  return false;
}

function collectSpans(text: string): Span[] {
  const spans: Span[] = [];
  if (hasAny(text, SECRET_MARKERS)) {
    for (const re of SECRET_RES) {
      for (const m of allMatches(re, text)) {
        if (m[0] === undefined || m.index === undefined) continue;
        if (re.source.includes('postgres') && /\$\{|^<[^>]+>$|^\{[^}]+\}$/.test(m[0])) continue;
        spans.push({ start: m.index, end: m.index + m[0].length, ruleId: 'DLP-SECRET-001', text: m[0] });
      }
    }
  }
  if (text.includes(' at ') || text.includes('Error') || text.includes('Exception')) {
    for (const m of allMatches(STACK_RE, text)) {
      if (m[0] === undefined || m.index === undefined) continue;
      spans.push({ start: m.index, end: m.index + m[0].length, ruleId: 'DLP-STACK-001', text: m[0] });
    }
  }
  if (/\d/.test(text)) {
    for (const m of allMatches(INTERNAL_IP_RE, text)) {
      if (m[0] === undefined || m.index === undefined) continue;
      spans.push({ start: m.index, end: m.index + m[0].length, ruleId: 'DLP-INTERNAL-001', text: m[0] });
    }
    spans.push(...findCards(text));
  }
  if (text.includes('localhost') || text.includes('LOCALHOST')) {
    spans.push(...findLocalhost(text));
  }
  if (
    text.includes('.internal') ||
    text.includes('.corp') ||
    text.includes('.lan') ||
    text.includes('.local') ||
    text.includes('.INTERNAL') ||
    text.includes('.CORP') ||
    text.includes('.LAN') ||
    text.includes('.LOCAL')
  ) {
    spans.push(...findInternalHosts(text));
  }
  return spans;
}

function isWord(c: string | undefined): boolean {
  return c !== undefined && /[A-Za-z0-9-]/.test(c);
}

function findIgnoreCase(hay: string, needle: string, from: number): number {
  const n = needle.length;
  outer: for (let i = from; i <= hay.length - n; i += 1) {
    for (let j = 0; j < n; j += 1) {
      const a = hay.charCodeAt(i + j);
      const b = needle.charCodeAt(j);
      if (a !== b && a !== b - 32 && a !== b + 32) continue outer;
    }
    return i;
  }
  return -1;
}

function findLocalhost(text: string): Span[] {
  const spans: Span[] = [];
  let from = 0;
  while (from < text.length) {
    const idx = findIgnoreCase(text, 'localhost', from);
    if (idx < 0) break;
    if (!isWord(text[idx - 1]) && !isWord(text[idx + 9])) {
      spans.push({ start: idx, end: idx + 9, ruleId: 'DLP-INTERNAL-001', text: text.slice(idx, idx + 9) });
    }
    from = idx + 9;
  }
  return spans;
}

function findInternalHosts(text: string): Span[] {
  const spans: Span[] = [];
  for (const tld of HOST_TLDS) {
    let from = 0;
    while (from < text.length) {
      const idx = findIgnoreCase(text, tld, from);
      if (idx < 0) break;
      let start = idx - 1;
      while (start >= 0 && /[A-Za-z0-9.-]/.test(text[start] ?? '')) start -= 1;
      start += 1;
      const label = text.slice(start, idx).toLowerCase();
      const end = idx + tld.length;
      if (label.length > 0 && /^[a-z0-9-]+(?:\.[a-z0-9-]+)*$/.test(label) && !isWord(text[end])) {
        spans.push({ start, end, ruleId: 'DLP-INTERNAL-001', text: text.slice(start, end) });
      }
      from = idx + tld.length;
    }
  }
  return spans;
}

function findCards(text: string): Span[] {
  const spans: Span[] = [];
  let i = 0;
  while (i < text.length) {
    const code = text.charCodeAt(i);
    if (code < 48 || code > 57) {
      i += 1;
      continue;
    }
    let j = i;
    let digits = '';
    while (j < text.length) {
      const c = text.charCodeAt(j);
      if (c >= 48 && c <= 57) {
        digits += text[j] ?? '';
        j += 1;
      } else if (c === 32 || c === 9 || c === 45) {
        j += 1;
      } else {
        break;
      }
    }
    if (luhnOk(digits)) {
      spans.push({ start: i, end: j, ruleId: 'DLP-CARD-001', text: text.slice(i, j) });
    }
    i = j > i ? j : i + 1;
  }
  return spans;
}

function findEmails(text: string): Span[] {
  const spans: Span[] = [];
  let from = 0;
  while (from < text.length) {
    const at = text.indexOf('@', from);
    if (at < 0) break;
    let start = at - 1;
    while (start >= 0 && /[A-Za-z0-9._%+-]/.test(text[start] ?? '')) start -= 1;
    start += 1;
    let end = at + 1;
    while (end < text.length && /[A-Za-z0-9.-]/.test(text[end] ?? '')) end += 1;
    const local = text.slice(start, at);
    const domain = text.slice(at + 1, end);
    const dot = domain.lastIndexOf('.');
    const tld = dot > 0 ? domain.slice(dot + 1) : '';
    if (
      local.length >= 1 &&
      local.length <= 64 &&
      domain.length >= 3 &&
      domain.length <= 255 &&
      /^[A-Za-z]{2,24}$/.test(tld)
    ) {
      spans.push({ start, end, ruleId: 'DLP-PII-001', text: text.slice(start, end) });
    }
    from = at + 1;
  }
  return spans;
}

function countEmails(text: string): { count: number; spans: Span[] } {
  if (!text.includes('@')) return { count: 0, spans: [] };
  const spans = findEmails(text);
  return { count: spans.length, spans };
}

function redact(text: string, spans: Span[]): string {
  const ordered = [...spans].sort((a, b) => b.start - a.start);
  let out = text;
  const taken: Array<[number, number]> = [];
  for (const s of ordered) {
    if (taken.some(([a, b]) => s.start < b && s.end > a)) continue;
    taken.push([s.start, s.end]);
    out = `${out.slice(0, s.start)}${REDACT}${out.slice(s.end)}`;
  }
  return out;
}

function uniqueHits(spans: Span[]): DlpHit[] {
  const seen = new Set<string>();
  const hits: DlpHit[] = [];
  for (const s of spans) {
    if (seen.has(s.ruleId)) continue;
    seen.add(s.ruleId);
    hits.push({ ruleId: s.ruleId, sample: maskSample(s.text) });
  }
  return hits;
}

function toText(body: unknown): { text: string; kind: 'string' | 'json' } | undefined {
  if (body === null || body === undefined) return undefined;
  if (typeof body === 'string') return { text: body, kind: 'string' };
  if (typeof body === 'number' || typeof body === 'boolean') return { text: String(body), kind: 'string' };
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(body)) return undefined;
  try {
    return { text: JSON.stringify(body), kind: 'json' };
  } catch {
    return undefined;
  }
}

interface RoutePii {
  samples: number;
  seenLow: boolean;
  seenHigh: boolean;
}

export function createDlpInspector(options: GuardOptions = {}): DlpInspector | undefined {
  if (!isDlpEnabled() || options.dlp === undefined) return undefined;
  const mode = options.dlp.mode;
  const maxBytes = options.dlp.maxBytes ?? DLP_MAX_BYTES;
  const routes = new Map<string, RoutePii>();
  let skipped = 0;

  const inspect = (body: unknown, ctx: { path: string; ip?: string; contentType?: string }): DlpInspectResult => {
    const ct = ctx.contentType ?? '';
    if (ct.length > 0 && !/json|text|javascript|xml/i.test(ct)) {
      return { action: 'allow', body, hits: [], skippedOverCap: false };
    }
    const serialized = toText(body);
    if (serialized === undefined) {
      return { action: 'allow', body, hits: [], skippedOverCap: false };
    }
    if (serialized.text.length > maxBytes) {
      skipped += 1;
      return { action: 'skip', body, hits: [], skippedOverCap: true };
    }
    const spans = collectSpans(serialized.text);
    const emails = countEmails(serialized.text);
    let pii = routes.get(ctx.path);
    if (pii === undefined) {
      pii = { samples: 0, seenLow: false, seenHigh: false };
      routes.set(ctx.path, pii);
    }
    if (pii.samples < PII_LEARN) {
      pii.samples += 1;
      if (emails.count <= 1) pii.seenLow = true;
      if (emails.count >= BULK_EMAILS) pii.seenHigh = true;
    } else if (pii.seenLow && !pii.seenHigh && emails.count >= BULK_EMAILS) {
      spans.push(...emails.spans);
    }
    const hits = uniqueHits(spans);
    if (hits.length === 0) {
      return { action: 'allow', body, hits: EMPTY_HITS, skippedOverCap: false };
    }
    const ip = ctx.ip ?? 'unknown';
    for (const hit of hits) {
      const event: GuardEvent = { ruleId: hit.ruleId, path: ctx.path, ip, sample: hit.sample };
      options.onEvent?.(event);
    }
    if (mode === 'monitor') {
      return { action: 'allow', body, hits, skippedOverCap: false };
    }
    if (mode === 'block') {
      return { action: 'block', body: { ...DLP_GENERIC }, hits, skippedOverCap: false };
    }
    const maskedText = redact(serialized.text, spans);
    let masked: unknown = maskedText;
    if (serialized.kind === 'json') {
      try {
        masked = JSON.parse(maskedText) as unknown;
      } catch {
        masked = maskedText;
      }
    }
    return { action: 'mask', body: masked, hits, skippedOverCap: false };
  };

  const api = inspect as unknown as DlpInspector;
  Object.defineProperty(api, 'inspect', { value: inspect });
  Object.defineProperty(api, 'skippedOverCap', { get: () => skipped });
  return api;
}

export function applyDlpWrite(
  dlp: DlpInspector,
  body: unknown,
  ctx: { path: string; ip?: string; contentType?: string },
): { body: unknown; block: boolean } {
  const result = dlp.inspect(body, ctx);
  return { body: result.body, block: result.action === 'block' };
}
