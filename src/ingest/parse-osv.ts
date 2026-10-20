import { IngestError } from './error.js';
import { makeItem, type IngestItem } from './item.js';
import { mapLabeledSeverity } from './severity.js';
import { advisoryIds, isRecord } from './text.js';

export function parseOsv(file: string, doc: unknown): IngestItem[] {
  if (!isRecord(doc) || !Array.isArray(doc.results)) {
    throw new IngestError(file, 'results must be an array');
  }
  const items: IngestItem[] = [];
  for (const result of doc.results) {
    if (!isRecord(result)) {continue;}
    if (!Array.isArray(result.packages)) {throw new IngestError(file, 'packages must be an array');}
    for (const pkg of result.packages) {
      if (isRecord(pkg)) {items.push(...packageItems(pkg));}
    }
  }
  return items;
}

function packageItems(pkg: Record<string, unknown>): IngestItem[] {
  const info = isRecord(pkg.package) ? pkg.package : undefined;
  const name = typeof info?.name === 'string' ? info.name : 'unknown';
  const version = typeof info?.version === 'string' && info.version.length > 0 ? info.version : 'unknown';
  if (!Array.isArray(pkg.vulnerabilities)) {return [];}
  const items: IngestItem[] = [];
  for (const vuln of pkg.vulnerabilities) {
    if (isRecord(vuln)) {items.push(vulnItem(name, version, vuln));}
  }
  return items;
}

function vulnItem(name: string, version: string, vuln: Record<string, unknown>): IngestItem {
  const ids = advisoryIds(`${typeof vuln.id === 'string' ? vuln.id : ''} ${aliasText(vuln.aliases)}`);
  const ruleId = ids[0] ?? 'osv-scanner';
  const title = typeof vuln.summary === 'string' ? vuln.summary : ruleId;
  const label = osvLabel(vuln);
  return makeItem({
    ruleId,
    externalRuleIds: ids.length > 0 ? ids : [ruleId],
    module: 'deps',
    title,
    severity: mapLabeledSeverity(label),
    externalSeverity: label,
    message: title,
    source: 'osv-scanner',
    snippet: `${name}@${version}`,
  });
}

function aliasText(aliases: unknown): string {
  if (!Array.isArray(aliases)) {return '';}
  return aliases.filter((item) => typeof item === 'string').join(' ');
}

function osvLabel(vuln: Record<string, unknown>): string {
  const db = isRecord(vuln.database_specific) ? vuln.database_specific : undefined;
  if (typeof db?.severity === 'string') {return db.severity;}
  return 'unset';
}
