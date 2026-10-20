import { isRecord } from './text.js';

export type IngestKind = 'sarif' | 'npm' | 'osv' | 'semgrep' | 'unknown';

export function detectKind(doc: unknown): IngestKind {
  if (!isRecord(doc)) {return 'unknown';}
  if (doc.version === '2.1.0' || schemaIsSarif(doc.$schema)) {return 'sarif';}
  if (doc.auditReportVersion !== undefined || isRecord(doc.advisories)) {return 'npm';}
  if (isNpmV2(doc)) {return 'npm';}
  if (isOsv(doc)) {return 'osv';}
  if (isSemgrep(doc)) {return 'semgrep';}
  return 'unknown';
}

function schemaIsSarif(schema: unknown): boolean {
  return typeof schema === 'string' && schema.toLowerCase().includes('sarif');
}

function isNpmV2(doc: Record<string, unknown>): boolean {
  if (!isRecord(doc.vulnerabilities) || !isRecord(doc.metadata)) {return false;}
  return isRecord(doc.metadata.vulnerabilities);
}

function isOsv(doc: Record<string, unknown>): boolean {
  if (!Array.isArray(doc.results)) {return false;}
  return doc.results.some((item) => isRecord(item) && Array.isArray(item.packages));
}

function isSemgrep(doc: Record<string, unknown>): boolean {
  if (!Array.isArray(doc.results)) {return false;}
  if (doc.results.length === 0) {return Array.isArray(doc.errors);}
  return doc.results.some((item) => isRecord(item) && typeof item.check_id === 'string');
}
