import { IngestError } from './error.js';
import { makeItem, type IngestItem } from './item.js';
import { mapLabeledSeverity } from './severity.js';
import { advisoryIds, firstCwe, isRecord } from './text.js';

export function parseNpm(file: string, doc: unknown): IngestItem[] {
  if (!isRecord(doc)) {throw new IngestError(file, 'npm audit document must be an object');}
  if (isRecord(doc.vulnerabilities)) {return parseV2(file, doc.vulnerabilities);}
  if (isRecord(doc.advisories)) {return parseLegacy(doc.advisories);}
  throw new IngestError(file, 'vulnerabilities must be an object');
}

function parseV2(file: string, vulns: Record<string, unknown>): IngestItem[] {
  const items: IngestItem[] = [];
  for (const vuln of Object.values(vulns)) {
    if (!isRecord(vuln)) {continue;}
    if (!Array.isArray(vuln.via)) {throw new IngestError(file, 'via must be an array');}
    const name = typeof vuln.name === 'string' ? vuln.name : 'unknown';
    const version = typeof vuln.version === 'string' && vuln.version.length > 0 ? vuln.version : 'unknown';
    for (const via of vuln.via) {
      if (!isRecord(via)) {continue;}
      items.push(viaItem(name, version, via, vuln.severity));
    }
  }
  return items;
}

function viaItem(
  name: string,
  version: string,
  via: Record<string, unknown>,
  fallback: unknown,
): IngestItem {
  const label = typeof via.severity === 'string' ? via.severity : typeof fallback === 'string' ? fallback : 'info';
  const ids = advisoryIds(viaText(via));
  const ruleId = ids[0] ?? 'npm-audit';
  const title = typeof via.title === 'string' ? via.title : ruleId;
  return makeItem({
    ruleId,
    externalRuleIds: ids.length > 0 ? ids : [ruleId],
    module: 'deps',
    title,
    severity: mapLabeledSeverity(label),
    externalSeverity: label,
    message: title,
    source: 'npm-audit',
    snippet: `${name}@${version}`,
    cwe: firstCwe(via.cwe),
  });
}

function viaText(via: Record<string, unknown>): string {
  const parts: string[] = [];
  if (typeof via.url === 'string') {parts.push(via.url);}
  if (typeof via.cve === 'string') {parts.push(via.cve);}
  if (Array.isArray(via.cves)) {
    for (const cve of via.cves) {if (typeof cve === 'string') {parts.push(cve);}}
  }
  return parts.join(' ');
}

function parseLegacy(advisories: Record<string, unknown>): IngestItem[] {
  const items: IngestItem[] = [];
  for (const advisory of Object.values(advisories)) {
    if (!isRecord(advisory)) {continue;}
    items.push(...legacyFindings(advisory));
  }
  return items;
}

function legacyFindings(advisory: Record<string, unknown>): IngestItem[] {
  const name = typeof advisory.module_name === 'string' ? advisory.module_name : 'unknown';
  const label = typeof advisory.severity === 'string' ? advisory.severity : 'info';
  const ids = advisoryIds(`${typeof advisory.url === 'string' ? advisory.url : ''} ${cveText(advisory.cves)}`);
  const ruleId = ids[0] ?? 'npm-audit';
  const title = typeof advisory.title === 'string' ? advisory.title : ruleId;
  const findings = Array.isArray(advisory.findings) ? advisory.findings : [];
  return findings.filter(isRecord).map((finding) => {
    const version = typeof finding.version === 'string' ? finding.version : 'unknown';
    return makeItem({
      ruleId,
      externalRuleIds: ids.length > 0 ? ids : [ruleId],
      module: 'deps',
      title,
      severity: mapLabeledSeverity(label),
      externalSeverity: label,
      message: title,
      source: 'npm-audit',
      snippet: `${name}@${version}`,
      cwe: firstCwe(advisory.cwe),
    });
  });
}

function cveText(cves: unknown): string {
  if (!Array.isArray(cves)) {return '';}
  return cves.filter((item) => typeof item === 'string').join(' ');
}
