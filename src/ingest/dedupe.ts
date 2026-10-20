import { sortFindings, type Finding } from '../core/finding.js';
import type { IngestItem } from './item.js';

interface Row {
  finding: Finding;
  fingerprints: Set<string>;
}

export function dedupeIngested(items: readonly IngestItem[]): Finding[] {
  const rows: Row[] = [];
  for (const item of items) {
    const match = rows.find((row) => sameRow(row, item));
    if (match === undefined) {
      rows.push({ finding: item.finding, fingerprints: new Set(item.fingerprints) });
      continue;
    }
    mergeInto(match.finding, item.finding);
    for (const fingerprint of item.fingerprints) {match.fingerprints.add(fingerprint);}
  }
  return sortFindings(rows.map((row) => row.finding));
}

function sameRow(row: Row, item: IngestItem): boolean {
  if (row.finding.module === 'deps' && item.finding.module === 'deps') {return sameDep(row.finding, item.finding);}
  if (row.finding.module !== 'deps' && item.finding.module !== 'deps') {return sameCode(row, item);}
  return false;
}

function sameDep(left: Finding, right: Finding): boolean {
  const a = packageOf(left.snippet);
  const b = packageOf(right.snippet);
  if (a === undefined || b === undefined) {return false;}
  if (a.name !== b.name || a.version !== b.version) {return false;}
  const ids = new Set(left.externalRuleIds ?? []);
  return (right.externalRuleIds ?? []).some((id) => ids.has(id));
}

function sameCode(row: Row, item: IngestItem): boolean {
  for (const fingerprint of item.fingerprints) {
    if (row.fingerprints.has(fingerprint)) {return true;}
  }
  const left = row.finding;
  const right = item.finding;
  if (left.cwe === undefined || left.cwe !== right.cwe) {return false;}
  if (left.file === undefined || left.file !== right.file) {return false;}
  if (left.line === undefined || right.line === undefined) {return false;}
  return Math.abs(left.line - right.line) <= 3;
}

function mergeInto(target: Finding, incoming: Finding): void {
  target.sources = union(target.sources, incoming.sources);
  const primary = target.sources[0];
  if (primary !== undefined) {target.source = primary;}
  preferRule(target, incoming);
  target.externalRuleIds = union(target.externalRuleIds, incoming.externalRuleIds);
  const other = target.externalRuleIds.find((id) => id !== target.ruleId);
  target.externalRuleId = other ?? target.externalRuleIds[0] ?? target.externalRuleId;
  copyEvidence(target, incoming);
}

function preferRule(target: Finding, incoming: Finding): void {
  if (isFullShieldRule(target.ruleId) || !isFullShieldRule(incoming.ruleId)) {return;}
  target.ruleId = incoming.ruleId;
  target.title = incoming.title;
  target.module = incoming.module;
  if (target.cwe === undefined && incoming.cwe !== undefined) {target.cwe = incoming.cwe;}
}

function copyEvidence(target: Finding, incoming: Finding): void {
  if (target.reachability === undefined && incoming.reachability !== undefined) {
    target.reachability = incoming.reachability;
  }
  if (target.sinkClass === undefined && incoming.sinkClass !== undefined) {target.sinkClass = incoming.sinkClass;}
  if (target.routeExposure === undefined && incoming.routeExposure !== undefined) {
    target.routeExposure = incoming.routeExposure;
  }
}

function union(left: readonly string[] | undefined, right: readonly string[] | undefined): string[] {
  return [...new Set([...(left ?? []), ...(right ?? [])])].sort();
}

function isFullShieldRule(ruleId: string): boolean {
  return /^(SAST|SECRET|SECRETS|CONFIG|DEPS|SUPPLY|HOST|MCP|AUTH)-/.test(ruleId);
}

function packageOf(snippet: string | undefined): { name: string; version: string } | undefined {
  if (snippet === undefined) {return undefined;}
  const at = snippet.lastIndexOf('@');
  if (at <= 0) {return undefined;}
  return { name: snippet.slice(0, at), version: snippet.slice(at + 1) };
}
