import { IngestError } from './error.js';
import { makeItem, type IngestItem } from './item.js';
import { mapSemgrepSeverity } from './severity.js';
import { firstCwe, isRecord, normPath } from './text.js';

export function parseSemgrep(file: string, doc: unknown): IngestItem[] {
  if (!isRecord(doc) || !Array.isArray(doc.results)) {
    throw new IngestError(file, 'results must be an array');
  }
  const items: IngestItem[] = [];
  for (const result of doc.results) {
    if (!isRecord(result)) {continue;}
    if (typeof result.check_id !== 'string') {throw new IngestError(file, 'check_id is required');}
    items.push(semgrepItem(result));
  }
  return items;
}

function semgrepItem(result: Record<string, unknown>): IngestItem {
  const checkId = result.check_id as string;
  const extra = isRecord(result.extra) ? result.extra : undefined;
  const label = typeof extra?.severity === 'string' ? extra.severity : 'INFO';
  const message = typeof extra?.message === 'string' ? extra.message : checkId;
  const metadata = extra !== undefined && isRecord(extra.metadata) ? extra.metadata : undefined;
  const start = isRecord(result.start) ? result.start : undefined;
  const line = typeof start?.line === 'number' ? start.line : undefined;
  const file = typeof result.path === 'string' ? normPath(result.path) : undefined;
  return makeItem({
    ruleId: checkId,
    externalRuleIds: [checkId],
    module: 'sast',
    title: message,
    severity: mapSemgrepSeverity(label),
    externalSeverity: label,
    message,
    source: 'semgrep',
    file,
    line,
    cwe: firstCwe(metadata?.cwe),
  });
}
