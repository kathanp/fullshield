import { spawn } from 'node:child_process';

import type { Finding } from '../core/finding.js';

export function applyDiffGate(
  findings: readonly Finding[],
  hunks: ReadonlyMap<string, ReadonlyArray<readonly [number, number]>>,
): Finding[] {
  return findings.map((finding) => {
    const file = (finding.file ?? '').split('\\').join('/');
    const line = finding.line;
    const ranges = hunks.get(file);
    const inside = line !== undefined && ranges !== undefined && ranges.some(([start, end]) => line >= start && line <= end);
    return inside ? finding : { ...finding, gate: false };
  });
}

function parseDiff(text: string): Map<string, Array<[number, number]>> {
  const hunks = new Map<string, Array<[number, number]>>();
  let file = '';
  for (const line of text.split('\n')) {
    if (line.startsWith('+++ b/')) {
      file = line.slice('+++ b/'.length);
      if (!hunks.has(file)) {hunks.set(file, []);}
      continue;
    }
    const match = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (match === null || file.length === 0) {continue;}
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    const end = count === 0 ? start : start + count - 1;
    hunks.get(file)?.push([start, end]);
  }
  return hunks;
}

function gitDiff(cwd: string): Promise<string | undefined> {
  return new Promise((resolve) => {
    const child = spawn('git', ['diff', '-U0', 'HEAD'], { cwd, stdio: ['ignore', 'pipe', 'ignore'] });
    let stdout = '';
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
    });
    child.once('exit', (code) => {
      resolve(code === 0 ? stdout : undefined);
    });
    child.once('error', () => {
      resolve(undefined);
    });
  });
}

/** Findings outside the working diff do not fail the gate. A git failure leaves them unchanged. */
export async function gateFindingsToDiff(cwd: string, findings: readonly Finding[]): Promise<Finding[]> {
  const text = await gitDiff(cwd);
  if (text === undefined) {return [...findings];}
  return applyDiffGate(findings, parseDiff(text));
}
