import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Finding } from '../core/finding.js';
import { fixVerifyEnabled, verifyProposedChange } from '../fixer/verify.js';

export class ExplainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ExplainError';
  }
}

export function matchFinding(findings: readonly Finding[], rawId: string): Finding {
  const id = rawId.trim();
  if (id.length < 6) {
    throw new ExplainError(`id prefix must be at least 6 characters (FULLSHIELD_EXPERIMENTAL_EXPLAIN)`);
  }
  const exact = findings.find((finding) => finding.id === id);
  if (exact !== undefined) return exact;
  const matches = findings.filter((finding) => finding.id.startsWith(id));
  if (matches.length === 1) {
    const only = matches[0];
    if (only !== undefined) return only;
  }
  if (matches.length === 0) {
    const candidates = findings.slice(0, 5).map((finding) => finding.id);
    throw new ExplainError(
      `no finding matches ${id}${candidates.length > 0 ? `; candidates: ${candidates.join(', ')}` : ''} (FULLSHIELD_EXPERIMENTAL_EXPLAIN)`,
    );
  }
  throw new ExplainError(
    `ambiguous id ${id}; candidates: ${matches.slice(0, 5).map((finding) => finding.id).join(', ')} (FULLSHIELD_EXPERIMENTAL_EXPLAIN)`,
  );
}

function contextLines(text: string, line: number | undefined): string[] {
  if (line === undefined) return [];
  const rows = text.split(/\r?\n/);
  const start = Math.max(0, line - 3);
  const end = Math.min(rows.length, line + 2);
  return rows.slice(start, end).map((row, index) => `${start + index + 1}|${row}`);
}

export function renderExplain(finding: Finding, fileText = ''): string {
  const location = finding.file !== undefined ? `${finding.file}${finding.line !== undefined ? `:${finding.line}` : ''}` : '(project)';
  const lines = [
    `${finding.ruleId} ${finding.title}`,
    `severity: ${finding.severity}`,
    `confidence: ${finding.confidence}`,
    `location: ${location}`,
  ];
  const context = contextLines(fileText, finding.line);
  if (context.length > 0) {
    lines.push('context:');
    lines.push(...context.map((row) => `  ${row}`));
  }
  if (finding.snippet !== undefined) lines.push(`snippet: ${finding.snippet}`);
  if (finding.trace !== undefined && finding.trace.length > 0) {
    lines.push(
      `trace: ${finding.trace.map((step) => `${step.file}${step.line !== undefined ? `:${step.line}` : ''} ${step.note}`).join(' → ')}`,
    );
  }
  if (finding.reachability !== undefined) {
    const path = finding.dependencyPath !== undefined ? ` (${finding.dependencyPath.join(' > ')})` : '';
    lines.push(`reachability: ${finding.reachability}${path}`);
  }
  if (finding.fix !== undefined) lines.push(`fix: ${finding.fix.diff}`);
  lines.push(`docs: rules/${finding.ruleId}.md`);
  return lines.join('\n');
}

export async function explainFinding(options: {
  cwd: string;
  id: string;
  findings: readonly Finding[];
  experimentalFixVerify?: boolean;
}): Promise<string> {
  const finding = matchFinding(options.findings, options.id);
  let text = '';
  if (finding.file !== undefined) {
    try {
      text = await readFile(join(options.cwd, finding.file), 'utf8');
    } catch {
      text = '';
    }
  }
  let rendered = renderExplain(finding, text);
  if (
    fixVerifyEnabled(options.experimentalFixVerify) &&
    finding.fix?.diff !== undefined &&
    finding.fix.diff.length > 0 &&
    finding.file !== undefined
  ) {
    const verdict = await verifyProposedChange({
      cwd: options.cwd,
      file: finding.file,
      ruleId: finding.ruleId,
      line: finding.line,
      diff: finding.fix.diff,
      base: text,
      finding,
    });
    rendered = `${rendered}\nverified: ${verdict.status}`;
  }
  return rendered;
}
