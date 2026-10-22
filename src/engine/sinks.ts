/** Phase 267. Static rules and RASP hooks share one catalog. */
export const SINKCATALOG_FLAG = 'FULLSHIELD_EXPERIMENTAL_SINKCATALOG';

export function sinkCatalogEnabled(): boolean {
  return process.env[SINKCATALOG_FLAG] === '1';
}

export interface SinkRow {
  package: string;
  member: string;
  argIndex: number;
  class: string;
  staticSupported: boolean;
  runtimeHook: string | null;
  runtimeGap?: string;
}

export function catalogGaps(rows: readonly SinkRow[]): SinkRow[] {
  return rows.filter((row) => {
    const staticOk = row.staticSupported === true;
    const hook = row.runtimeHook !== null && row.runtimeHook !== '';
    const gap = typeof row.runtimeGap === 'string' && row.runtimeGap.length > 0;
    if (staticOk && !hook && !gap) {return true;}
    if (hook && !staticOk && !gap) {return true;}
    return false;
  });
}

export function gapMarkdown(rows: readonly SinkRow[]): string {
  const gaps = catalogGaps(rows);
  const lines = ['# RASP sink gaps', '', 'Generated from models/sinks.json. A static sink needs a runtime hook or a runtimeGap.', ''];
  if (gaps.length === 0) {lines.push('No undocumented gaps.');}
  for (const gap of gaps) {lines.push(`- ${gap.package}.${gap.member}`);}
  return lines.join('\n');
}

export function readSinkCatalog(raw: unknown): SinkRow[] {
  if (!sinkCatalogEnabled()) {return [];}
  if (typeof raw !== 'object' || raw === null || !('sinks' in raw) || !Array.isArray(raw.sinks)) {return [];}
  const rows: SinkRow[] = [];
  for (const row of raw.sinks) {
    if (typeof row !== 'object' || row === null) {continue;}
    const record = row as Record<string, unknown>;
    if (typeof record.package !== 'string' || typeof record.member !== 'string') {continue;}
    const hook = record.runtimeHook;
    rows.push({
      package: record.package,
      member: record.member,
      argIndex: typeof record.argIndex === 'number' ? record.argIndex : 0,
      class: typeof record.class === 'string' ? record.class : '',
      staticSupported: record.staticSupported === true,
      runtimeHook: typeof hook === 'string' ? hook : null,
      runtimeGap: typeof record.runtimeGap === 'string' ? record.runtimeGap : undefined,
    });
  }
  return rows;
}
