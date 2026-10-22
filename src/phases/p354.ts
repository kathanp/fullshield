/**
 * Phase 354. Static string folding.
 * Off unless FULLSHIELD_EXPERIMENTAL_DEOBFUSC=1.
 * Folds a fixed set of string operations. eval and Function stop the fold.
 */

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_DEOBFUSC';
export const FOLD_MAX_LENGTH = 256;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface FoldResult {
  text: string;
  partial: boolean;
  events: string[];
}

function decodeLiteral(body: string): string {
  return body.replace(/\\x([0-9a-fA-F]{2})/g, (_all, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
}

export function foldSource(source: string): FoldResult {
  if (!enabled()) {
    return { text: source, partial: false, events: [] };
  }
  if (/\beval\s*\(/.test(source) || /\bFunction\s*\(/.test(source)) {
    return { text: source, partial: false, events: ['fold stopped at eval'] };
  }
  let partial = false;
  const events: string[] = [];
  let text = source;
  text = text.replace(/String\.fromCharCode\(([^)]*)\)/g, (all, inner: string) => {
    const parts = inner.split(',').map((part) => part.trim());
    if (parts.some((part) => !/^\d+$/.test(part))) {
      return all;
    }
    const folded = parts.map((part) => String.fromCharCode(Number.parseInt(part, 10))).join('');
    return `'${folded.replaceAll("'", "\\'")}'`;
  });
  text = text.replace(/'([^']*)'\.split\(''\)\.reverse\(\)\.join\(''\)/g, (_all, body: string) => `'${[...body].reverse().join('')}'`);
  text = text.replace(/Buffer\.from\(\s*'([^']*)'\s*,\s*'(base64|hex)'\s*\)/g, (_all, body: string, encoding: string) => {
    const decoded = Buffer.from(body, encoding === 'hex' ? 'hex' : 'base64').toString('utf8');
    if (decoded.length > FOLD_MAX_LENGTH) {
      partial = true;
      events.push('fold was partial');
      return `'${decoded.slice(0, FOLD_MAX_LENGTH)}'`;
    }
    return `'${decoded.replaceAll("'", "\\'")}'`;
  });
  text = text.replace(/'([^']*)'\s*\+\s*'([^']*)'/g, (_all, left: string, right: string) => `'${decodeLiteral(left)}${decodeLiteral(right)}'`);
  if (text.length > source.length + FOLD_MAX_LENGTH) {
    partial = true;
    events.push('fold was partial');
    text = text.slice(0, source.length + FOLD_MAX_LENGTH);
  }
  return { text, partial, events };
}
