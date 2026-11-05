import type { Finding } from '../../core/finding.js';

const SAMPLE_DIRS = new Set(['test', '__tests__', 'examples', 'example', 'fixtures']);

const SAMPLE_RULES = new Set([
  'CONFIG-HELMET-001',
  'CONFIG-ERRSTACK-001',
  'CONFIG-RATELIMIT-001',
  'CONFIG-BODYLIMIT-001',
  'CONFIG-DOCKER-ROOT-001',
]);

/** App-config noise lives in tests, examples, and fixtures. Other rules still run there. */
export function isSampleConfigPath(file: string): boolean {
  const parts = file.split('\\').join('/').split('/');
  if (parts.some((part) => SAMPLE_DIRS.has(part))) {return true;}
  const base = parts[parts.length - 1] ?? '';
  return base.includes('.test.');
}

export function omitSampleConfigFindings(file: string, findings: readonly Finding[]): Finding[] {
  if (!isSampleConfigPath(file)) {return [...findings];}
  return findings.filter((finding) => !SAMPLE_RULES.has(finding.ruleId));
}
