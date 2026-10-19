import { readFile } from 'node:fs/promises';

import { makeFindingId, type Finding, type Severity } from '../core/finding.js';

export class IngestError extends Error {
  constructor(file: string, detail: string) {
    super(`cannot ingest ${file}: ${detail} (FULLSHIELD_EXPERIMENTAL_INGEST)`);
  }
}

interface RawRow {
  tool: Finding['source'];
  externalRuleId: string;
  severity: Severity;
  file?: string;
  line?: number;
  message: string;
  packageName?: string;
  version?: string;
  advisoryId?: string;
  cwe?: string;
}

function textOf(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value : fallback;
}

function unknownArray(value: unknown): unknown[] {
  if (!Array.isArray(value)) return [];
  const out: unknown[] = [];
  for (const item of value) out.push(item);
  return out;
}

function severityOf(value: string | undefined): Severity {
  const name = (value ?? 'medium').toLowerCase();
  if (name === 'critical' || name === 'error') return 'high';
  if (name === 'high' || name === 'warning') return name === 'warning' ? 'medium' : 'high';
  if (name === 'moderate') return 'medium';
  if (name === 'low' || name === 'note') return 'low';
  if (name === 'info') return 'info';
  if (name === 'medium') return 'medium';
  return 'medium';
}

function asRecord(value: unknown, file: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object') throw new IngestError(file, 'JSON root is not an object');
  return value as Record<string, unknown>;
}

export function parseIngestFile(file: string, text: string): RawRow[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (error) {
    throw new IngestError(file, error instanceof Error ? error.message : 'invalid JSON');
  }
  const root = asRecord(parsed, file);
  if (root.version === '2.1.0' && Array.isArray(root.runs)) return parseSarif(file, root);
  if (Array.isArray(root.results) && root.results.some((item) => item !== null && typeof item === 'object' && 'check_id' in (item as object))) {
    return parseSemgrep(file, root);
  }
  if (Array.isArray(root.results)) return parseOsv(file, root);
  if (root.vulnerabilities !== undefined || root.auditReportVersion !== undefined) return parseNpmAudit(file, root);
  throw new IngestError(file, 'unrecognized report shape');
}

function parseSemgrep(file: string, root: Record<string, unknown>): RawRow[] {
  const results = root.results;
  if (!Array.isArray(results)) throw new IngestError(file, 'semgrep results missing');
  return results.map((item) => {
    const row = asRecord(item, file);
    const extra = asRecord(row.extra ?? {}, file);
    const start = asRecord(row.start ?? {}, file);
    const metadata = extra.metadata !== undefined ? asRecord(extra.metadata, file) : {};
    const cweRaw = unknownArray(metadata.cwe).find((item) => typeof item === 'string') ?? metadata.cwe;
    return {
      tool: 'semgrep' as const,
      externalRuleId: textOf(row.check_id, 'semgrep'),
      severity: severityOf(typeof extra.severity === 'string' ? extra.severity : undefined),
      file: typeof row.path === 'string' ? row.path : undefined,
      line: typeof start.line === 'number' ? start.line : undefined,
      message: typeof extra.message === 'string' ? extra.message : 'Semgrep finding',
      cwe: typeof cweRaw === 'string' ? cweRaw : undefined,
    };
  });
}

function parseOsv(file: string, root: Record<string, unknown>): RawRow[] {
  const rows: RawRow[] = [];
  const results = root.results;
  if (!Array.isArray(results)) throw new IngestError(file, 'osv results missing');
  for (const result of results) {
    const packages = asRecord(result, file).packages;
    if (!Array.isArray(packages)) continue;
    for (const item of packages) {
      const pkg = asRecord(item, file);
      const identity = asRecord(pkg.package ?? {}, file);
      const vulns = pkg.vulnerabilities;
      if (!Array.isArray(vulns)) continue;
      for (const vuln of vulns) {
        const advisory = asRecord(vuln, file);
        rows.push({
        tool: 'osv-scanner',
        externalRuleId: textOf(advisory.id, 'OSV'),
        severity: 'high',
        message: textOf(advisory.summary, textOf(advisory.id, 'OSV advisory')),
        packageName: typeof identity.name === 'string' ? identity.name : undefined,
          version: typeof identity.version === 'string' ? identity.version : undefined,
          advisoryId: typeof advisory.id === 'string' ? advisory.id : undefined,
        });
      }
    }
  }
  return rows;
}

function parseNpmAudit(file: string, root: Record<string, unknown>): RawRow[] {
  const vulns = root.vulnerabilities;
  if (vulns === null || typeof vulns !== 'object') throw new IngestError(file, 'npm audit vulnerabilities missing');
  const rows: RawRow[] = [];
  for (const [name, value] of Object.entries(vulns as Record<string, unknown>)) {
    const row = asRecord(value, file);
    const via = unknownArray(row.via);
    const advisory = via.find((item) => item !== null && typeof item === 'object');
    const info = advisory !== undefined ? asRecord(advisory, file) : {};
    const url = typeof info.url === 'string' ? info.url : '';
    const ghsa = /GHSA-[0-9a-z-]+/i.exec(url)?.[0];
    rows.push({
      tool: 'npm-audit',
      externalRuleId: ghsa ?? textOf(info.source, name),
      severity: severityOf(typeof row.severity === 'string' ? row.severity : undefined),
      message: typeof info.title === 'string' ? info.title : `npm audit ${name}`,
      packageName: name,
      advisoryId: ghsa,
    });
  }
  return rows;
}

function parseSarif(file: string, root: Record<string, unknown>): RawRow[] {
  const rows: RawRow[] = [];
  const runs = root.runs;
  if (!Array.isArray(runs)) throw new IngestError(file, 'sarif runs missing');
  for (const run of runs) {
    const results = asRecord(run, file).results;
    if (!Array.isArray(results)) continue;
    for (const result of results) {
      const row = asRecord(result, file);
      const locations = Array.isArray(row.locations) ? row.locations : [];
      const first = locations[0] !== undefined ? asRecord(locations[0], file) : {};
      const physical = first.physicalLocation !== undefined ? asRecord(first.physicalLocation, file) : {};
      const artifact = physical.artifactLocation !== undefined ? asRecord(physical.artifactLocation, file) : {};
      const region = physical.region !== undefined ? asRecord(physical.region, file) : {};
      const message = row.message !== undefined ? asRecord(row.message, file) : {};
      rows.push({
        tool: 'sarif',
        externalRuleId: textOf(row.ruleId, 'sarif'),
        severity: severityOf(typeof row.level === 'string' ? row.level : undefined),
        file: typeof artifact.uri === 'string' ? artifact.uri : undefined,
        line: typeof region.startLine === 'number' ? region.startLine : undefined,
        message: typeof message.text === 'string' ? message.text : 'SARIF result',
      });
    }
  }
  return rows;
}

function toFinding(row: RawRow): Finding {
  const snippet = row.packageName ?? row.message;
  return {
    id: makeFindingId(row.externalRuleId, row.file ?? row.packageName, snippet),
    ruleId: row.packageName !== undefined ? 'DEPS-VULN-001' : row.externalRuleId,
    externalRuleId: row.externalRuleId,
    module: row.packageName !== undefined ? 'deps' : 'sast',
    title: row.message,
    severity: row.severity,
    confidence: 'medium',
    cwe: row.cwe,
    file: row.file,
    line: row.line,
    snippet,
    message: row.message,
    remediation: 'See the original tool report.',
    source: row.tool,
    sources: [row.tool ?? 'sarif'],
    references: row.advisoryId !== undefined ? [row.advisoryId] : undefined,
  };
}

function sameCode(left: Finding, right: Finding): boolean {
  if (left.module !== 'sast' || right.module !== 'sast') return false;
  if (left.file === undefined || left.file !== right.file) return false;
  if (left.cwe !== undefined && right.cwe !== undefined && left.cwe !== right.cwe) return false;
  if (left.line === undefined || right.line === undefined) return left.externalRuleId === right.externalRuleId;
  return Math.abs(left.line - right.line) <= 3;
}

function sameDep(left: Finding, right: Finding): boolean {
  if (left.module !== 'deps' || right.module !== 'deps') return false;
  const leftId = left.references?.[0] ?? left.externalRuleId;
  const rightId = right.references?.[0] ?? right.externalRuleId;
  return leftId === rightId && left.snippet === right.snippet;
}

export function dedupeIngest(rows: RawRow[]): Finding[] {
  const findings = rows.map(toFinding);
  const merged: Finding[] = [];
  for (const finding of findings) {
    const existing = merged.find((item) => sameDep(item, finding) || sameCode(item, finding));
    if (existing === undefined) {
      merged.push(finding);
      continue;
    }
    const sources = new Set([...(existing.sources ?? []), ...(finding.sources ?? [])]);
    existing.sources = [...sources];
  }
  return merged;
}

export async function ingestFiles(paths: readonly string[]): Promise<Finding[]> {
  const rows: RawRow[] = [];
  for (const file of paths) {
    let text: string;
    try {
      text = await readFile(file, 'utf8');
    } catch (error) {
      throw new IngestError(file, error instanceof Error ? error.message : 'unreadable');
    }
    rows.push(...parseIngestFile(file, text));
  }
  return dedupeIngest(rows);
}
