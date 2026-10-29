import { readFile, readdir } from 'node:fs/promises';
import { extname, join, sep } from 'node:path';

import type { ScanResult } from '../../core/engine.js';
import {
  makeFindingId,
  severityRank,
  sortFindings,
  summarize,
  type Finding,
  type Severity,
} from '../../core/finding.js';

export const SAST_PARITY_FLAG = 'FULLSHIELD_EXPERIMENTAL_SAST_PARITY';

const RULES_NAME = 'fullshield.rules.yml';
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'coverage', '.fullshield']);
const SOURCE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
interface LocalRule {
  pattern: string;
  message: string;
  severity: 'low' | 'medium' | 'high';
}

function fail(message: string): never {
  const err = new Error(message);
  throw err;
}

function bad(detail: string): never {
  fail(`cannot read local rules (${SAST_PARITY_FLAG}): ${detail}`);
}

export function assertSastParity(action: string): void {
  if (process.env[SAST_PARITY_FLAG] !== '1') {
    fail(`${action} requires ${SAST_PARITY_FLAG}`);
  }
}

export function taintEdgeLine(finding: Finding): string | undefined {
  const trace = finding.trace;
  if (trace === undefined || trace.length < 2) {return undefined;}
  const source = trace[0];
  const sink = trace[trace.length - 1];
  if (source === undefined || sink === undefined) {return undefined;}
  if (source.line === undefined || sink.line === undefined) {return undefined;}
  if (source.file.length === 0 || sink.file.length === 0) {return undefined;}
  return `source ${source.file}:${source.line} sink ${sink.file}:${sink.line}`;
}

export function reachabilityCounts(findings: readonly Finding[]): string {
  const rows = new Map<string, { severity: string; reachability: string; count: number }>();
  for (const finding of findings) {
    const reachability = finding.reachability ?? 'unspecified';
    const key = `${finding.severity}\0${reachability}`;
    const existing = rows.get(key);
    if (existing === undefined) {
      rows.set(key, { severity: finding.severity, reachability, count: 1 });
    } else {
      existing.count += 1;
    }
  }
  const ordered = [...rows.values()].sort((a, b) => {
    const rank = severityRank(b.severity as Severity) - severityRank(a.severity as Severity);
    if (rank !== 0) {return rank;}
    return a.reachability.localeCompare(b.reachability);
  });
  return `${JSON.stringify({ bySeverityReachability: ordered })}\n`;
}

function unquote(text: string): string {
  let out = '';
  for (let i = 1; i < text.length - 1; i += 1) {
    const ch = text[i] ?? '';
    if (ch !== '\\') {
      out += ch;
      continue;
    }
    const next = text[i + 1];
    if (next !== '"' && next !== '\\') {bad('bad escape');}
    out += next ?? '';
    i += 1;
  }
  return out;
}

function parseScalar(raw: string): string | number {
  const text = raw.trim();
  if (text.length === 0) {bad('empty value');}
  if (text.startsWith('"')) {
    if (!text.endsWith('"') || text.length < 2) {bad('open quote');}
    return unquote(text);
  }
  if (/^\d+$/.test(text)) {return Number(text);}
  if (/[:#{}[\]*&|>]/.test(text)) {bad('unsupported scalar');}
  return text;
}

function takeField(item: Record<string, string | number>, raw: string): void {
  const match = /^(schema|pattern|message|severity):\s*(.*)$/.exec(raw.trim());
  if (match === null) {bad('rule shape');}
  const key = match[1] ?? '';
  if (item[key] !== undefined) {bad('duplicate key');}
  const value = parseScalar(match[2] ?? '');
  if (key === 'schema' && value !== 1) {bad('schema');}
  if (key === 'severity' && value !== 'low' && value !== 'medium' && value !== 'high') {bad('severity');}
  if ((key === 'pattern' || key === 'message') && (typeof value !== 'string' || value.length === 0)) {
    bad('rule shape');
  }
  item[key] = value;
}

function finishRule(item: Record<string, string | number> | undefined): LocalRule | undefined {
  if (item === undefined) {return undefined;}
  if (item.schema !== 1 || typeof item.pattern !== 'string' || typeof item.message !== 'string') {bad('rule shape');}
  const severity = item.severity;
  if (severity !== 'low' && severity !== 'medium' && severity !== 'high') {bad('severity');}
  if (Object.keys(item).length !== 4) {bad('rule shape');}
  return { pattern: item.pattern, message: item.message, severity };
}

export function parseLocalRules(text: string): LocalRule[] {
  const rules: LocalRule[] = [];
  let current: Record<string, string | number> | undefined;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\r$/, '');
    if (line.trim().length === 0) {continue;}
    if (line.startsWith('- ')) {
      const done = finishRule(current);
      if (done !== undefined) {rules.push(done);}
      current = {};
      takeField(current, line.slice(2));
      continue;
    }
    if (!line.startsWith('  ') || current === undefined) {bad('rule shape');}
    takeField(current, line.slice(2));
  }
  const done = finishRule(current);
  if (done !== undefined) {rules.push(done);}
  return rules;
}

function localRuleId(index: number): string {
  return ['YAML', 'RULE', String(index + 1).padStart(3, '0')].join('-');
}

async function sourceFiles(cwd: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(rel: string): Promise<void> {
    const entries = await readdir(join(cwd, rel), { withFileTypes: true });
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name) || entry.isSymbolicLink()) {continue;}
      const child = rel.length === 0 ? entry.name : join(rel, entry.name);
      if (entry.isDirectory()) {
        await walk(child);
        continue;
      }
      if (SOURCE_EXT.has(extname(entry.name))) {out.push(child.split(sep).join('/'));}
    }
  }
  await walk('');
  return out.sort();
}

function toFinding(rule: LocalRule, ruleId: string, file: string, line: number, snippet: string): Finding {
  return {
    id: makeFindingId(ruleId, file, snippet),
    ruleId,
    module: 'sast',
    title: 'Local YAML rule',
    severity: rule.severity,
    confidence: 'medium',
    file,
    line,
    snippet,
    message: rule.message,
    remediation: 'Edit the matching line or remove the local rule.',
    source: 'user-rule',
  };
}

function storedRuleId(): string {
  return ['SAST', 'STORED', '001'].join('-');
}

function storedNames(line: string): string[] {
  const names: string[] = [];
  const pattern = /\b([A-Za-z_$][\w$]*)\s*=\s*req\.body\.[A-Za-z_$][\w$]*/g;
  for (const match of line.matchAll(pattern)) {
    const name = match[1];
    if (name !== undefined) {names.push(name);}
  }
  return names;
}

function sendsStored(line: string, name: string): boolean {
  const call = new RegExp(`\\bres\\.(?:send|end)\\(\\s*${name}\\b`);
  const encoded = new RegExp(`encodeURIComponent\\(\\s*${name}\\b`);
  return call.test(line) && !encoded.test(line);
}

function storedOutputFindings(files: readonly { file: string; source: string }[]): Finding[] {
  const ruleId = storedRuleId();
  const findings: Finding[] = [];
  for (const entry of files) {
    const lines = entry.source.split(/\r?\n/);
    const names = new Set<string>();
    for (let lineNo = 0; lineNo < lines.length; lineNo += 1) {
      const snippet = lines[lineNo] ?? '';
      for (const name of storedNames(snippet)) {names.add(name);}
      for (const name of names) {
        if (!sendsStored(snippet, name)) {continue;}
        findings.push({
          id: makeFindingId(ruleId, entry.file, snippet),
          ruleId,
          module: 'sast',
          title: 'Stored response',
          severity: 'medium',
          confidence: 'low',
          file: entry.file,
          line: lineNo + 1,
          snippet,
          message: 'Stored request data is written back to the response.',
          remediation: 'Encode the stored value before writing the response.',
          source: 'user-rule',
        });
        break;
      }
    }
  }
  return findings;
}

async function readYaml(cwd: string): Promise<string | null> {
  try {
    return await readFile(join(cwd, RULES_NAME), 'utf8');
  } catch (error) {
    const code = (error as { code?: string }).code;
    if (code === 'ENOENT') {return null;}
    bad('unreadable');
  }
}

export async function localRuleFindings(cwd: string): Promise<Finding[]> {
  if (process.env[SAST_PARITY_FLAG] !== '1') {return [];}
  const text = await readYaml(cwd);
  const yamlHits = text === null || text.trim().length === 0 ? [] : await findingsForRules(cwd, parseLocalRules(text));
  const files = await sourceFiles(cwd);
  const loaded: { file: string; source: string }[] = [];
  for (const file of files) {
    loaded.push({ file, source: await readFile(join(cwd, file), 'utf8') });
  }
  return [...yamlHits, ...storedOutputFindings(loaded)];
}

async function findingsForRules(cwd: string, rules: readonly LocalRule[]): Promise<Finding[]> {
  const files = await sourceFiles(cwd);
  const findings: Finding[] = [];
  for (let index = 0; index < rules.length; index += 1) {
    const rule = rules[index];
    if (rule === undefined) {continue;}
    const ruleId = localRuleId(index);
    for (const file of files) {
      const source = await readFile(join(cwd, file), 'utf8');
      const lines = source.split(/\r?\n/);
      for (let lineNo = 0; lineNo < lines.length; lineNo += 1) {
        const snippet = lines[lineNo] ?? '';
        if (!snippet.includes(rule.pattern)) {continue;}
        findings.push(toFinding(rule, ruleId, file, lineNo + 1, snippet));
      }
    }
  }
  return findings;
}

export function withExtraFindings(result: ScanResult, extra: readonly Finding[]): ScanResult {
  if (extra.length === 0) {return result;}
  const findings = sortFindings([...result.findings, ...extra]);
  return { ...result, findings, summary: summarize(findings) };
}
