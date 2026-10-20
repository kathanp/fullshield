import { validateSarif21 } from '../reporters/sarif.js';
import { IngestError } from './error.js';
import { evidenceOf, makeItem, type IngestItem } from './item.js';
import { sarifSeverity } from './severity.js';
import { fingerprintValues, firstCwe, isRecord, normPath } from './text.js';

export function parseSarif(file: string, doc: unknown): IngestItem[] {
  const errors = validateSarif21(doc);
  const first = errors[0];
  if (first !== undefined) {throw new IngestError(file, first);}
  const root = doc as Record<string, unknown>;
  const items: IngestItem[] = [];
  for (const run of root.runs as unknown[]) {
    if (!isRecord(run)) {continue;}
    items.push(...runItems(run));
  }
  return items;
}

function runItems(run: Record<string, unknown>): IngestItem[] {
  const tool = isRecord(run.tool) ? run.tool : undefined;
  const driver = tool !== undefined && isRecord(tool.driver) ? tool.driver : undefined;
  const source = typeof driver?.name === 'string' ? driver.name : 'sarif';
  if (!Array.isArray(run.results)) {return [];}
  const items: IngestItem[] = [];
  for (const result of run.results) {
    if (isRecord(result)) {items.push(resultItem(source, result));}
  }
  return items;
}

function resultItem(source: string, result: Record<string, unknown>): IngestItem {
  const props = isRecord(result.properties) ? result.properties : undefined;
  const named = typeof props?.severity === 'string' ? props.severity : undefined;
  const level = typeof result.level === 'string' ? result.level : 'none';
  const mapped = sarifSeverity(level, named);
  const ruleId = typeof result.ruleId === 'string' ? result.ruleId : source;
  const message = messageText(result.message);
  const place = locationOf(result.locations);
  const evidence = evidenceOf(props);
  return makeItem({
    ruleId,
    externalRuleIds: [ruleId],
    module: 'sast',
    title: message,
    severity: mapped.severity,
    externalSeverity: mapped.external,
    message,
    source,
    file: place.file,
    line: place.line,
    cwe: firstCwe(result.taxa, props?.cwe, props?.tags),
    fingerprints: fingerprintValues(result.partialFingerprints),
    ...evidence,
  });
}

function messageText(message: unknown): string {
  if (!isRecord(message)) {return 'SARIF result';}
  if (typeof message.text === 'string') {return message.text;}
  if (typeof message.id === 'string') {return message.id;}
  return 'SARIF result';
}

function locationOf(locations: unknown): { file?: string; line?: number } {
  if (!Array.isArray(locations) || !isRecord(locations[0])) {return {};}
  const physical = locations[0].physicalLocation;
  if (!isRecord(physical)) {return {};}
  const artifact = physical.artifactLocation;
  const region = physical.region;
  const uri = isRecord(artifact) && typeof artifact.uri === 'string' ? normPath(artifact.uri) : undefined;
  const line = isRecord(region) && typeof region.startLine === 'number' ? region.startLine : undefined;
  return { file: uri, line };
}
