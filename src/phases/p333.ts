/**
 * Phase 333. Entropy model v2.
 * Off unless FULLSHIELD_EXPERIMENTAL_ENTROPY2=1.
 * Shannon entropy with fixed rejects. Automation may not edit the threshold file.
 */

import { MINIFIED_MAX_NEWLINE_RATIO, MINIFIED_MIN_BYTES } from './p363.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_ENTROPY2';
export const THRESHOLD_ID = 'shannon-v2';
export const ENTROPY_FLOOR = 4.5;
export const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export const DICTIONARY = ['password', 'changeme', 'secret', 'token', 'example', 'test', 'admin', 'undefined', 'function'] as const;
const WORDS = new Set<string>(DICTIONARY);

export interface EntropyInput {
  span: string;
  file: string;
  line: number;
  formatMatched?: boolean;
  fileText?: string;
}

export interface EntropyFinding {
  ruleId: 'SECRETS-ENTROPY-001';
  severity: 'medium';
  confidence: 'low';
  file: string;
  line: number;
  message: string;
  witness: string;
}

export type EntropyReject = 'dictionary' | 'hex-color' | 'uuid' | 'empty-sha256' | 'minified' | 'format' | 'below-threshold';

export function shannon(span: string): number {
  if (span.length === 0) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const char of span) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / span.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

export function isMinifiedDensity(text: string): boolean {
  if (text.length <= MINIFIED_MIN_BYTES) {
    return false;
  }
  let newlines = 0;
  for (const char of text) {
    if (char === '\n') {
      newlines += 1;
    }
  }
  return newlines / text.length < MINIFIED_MAX_NEWLINE_RATIO;
}

export function entropyReject(input: EntropyInput): EntropyReject | undefined {
  if (input.formatMatched === true) {
    return 'format';
  }
  if (input.fileText !== undefined && isMinifiedDensity(input.fileText)) {
    return 'minified';
  }
  const span = input.span.trim();
  if (WORDS.has(span.toLowerCase())) {
    return 'dictionary';
  }
  if (/^[0-9a-fA-F]{3}$/.test(span) || /^[0-9a-fA-F]{6}$/.test(span) || /^[0-9a-fA-F]{8}$/.test(span)) {
    return 'hex-color';
  }
  if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(span)) {
    return 'uuid';
  }
  if (span.toLowerCase() === EMPTY_SHA256) {
    return 'empty-sha256';
  }
  if (shannon(span) < ENTROPY_FLOOR) {
    return 'below-threshold';
  }
  return undefined;
}

export function entropyFindings(inputs: readonly EntropyInput[]): EntropyFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: EntropyFinding[] = [];
  for (const input of inputs) {
    if (entropyReject(input) !== undefined) {
      continue;
    }
    const bits = shannon(input.span.trim());
    findings.push({
      ruleId: 'SECRETS-ENTROPY-001',
      severity: 'medium',
      confidence: 'low',
      file: input.file,
      line: input.line,
      message: `Span entropy ${bits.toFixed(2)} meets ${THRESHOLD_ID}.`,
      witness: `${THRESHOLD_ID} ${bits.toFixed(2)}`,
    });
  }
  return findings;
}

export function thresholdOwnership(commit: { author: string; files: readonly string[] }): void {
  const author = commit.author.trim().toLowerCase();
  const automation = author.includes('cursor') || author.includes('automation');
  const touched = commit.files.some((file) => file.replaceAll('\\', '/').endsWith('quality/entropy-thresholds.json'));
  if (automation && touched) {
    throw new Error('threshold file is human-owned');
  }
}
