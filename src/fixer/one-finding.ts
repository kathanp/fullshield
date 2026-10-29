import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { scan } from '../core/engine.js';
import type { Finding } from '../core/finding.js';
import { assertSastParity, SAST_PARITY_FLAG } from '../modules/sast/parity.js';
import { isDirty, isGitRepo } from './git.js';
import { applyUnifiedDiff, proposeFix } from './patches.js';

function fail(message: string): never {
  const err = new Error(message);
  throw err;
}

function parseFindingSelector(selector: string): { ruleId: string; file: string; line: number } {
  const match = /^([^:]+):(.+):(\d+)$/.exec(selector);
  if (match === null) {fail(`fix --finding selector is ruleId:file:line (${SAST_PARITY_FLAG})`);}
  const line = Number(match[3]);
  const file = match[2] ?? '';
  if (!Number.isInteger(line) || line < 1 || file.length === 0 || file.includes('..') || file.startsWith('/')) {
    fail(`fix --finding selector is ruleId:file:line (${SAST_PARITY_FLAG})`);
  }
  return { ruleId: match[1] ?? '', file, line };
}

async function assertWritable(cwd: string, force: boolean): Promise<void> {
  if (force) {return;}
  if (!(await isGitRepo(cwd))) {fail(`fix --finding requires a git repository (${SAST_PARITY_FLAG})`);}
  if (await isDirty(cwd)) {fail(`fix --finding requires a clean git tree (${SAST_PARITY_FLAG})`);}
}

export async function applyOneSafeFix(input: {
  cwd: string;
  selector: string;
  force: boolean;
  findings?: readonly Finding[];
}): Promise<{ file: string }> {
  assertSastParity('fix --finding');
  const target = parseFindingSelector(input.selector);
  const findings = input.findings ?? (await scan({ cwd: input.cwd })).findings;
  const matches = findings.filter(
    (finding) => finding.ruleId === target.ruleId && finding.file === target.file && finding.line === target.line,
  );
  if (matches.length !== 1) {fail(`fix --finding did not match one finding (${SAST_PARITY_FLAG})`);}
  const match = matches[0];
  if (match === undefined || match.file === undefined) {fail(`fix --finding did not match one finding (${SAST_PARITY_FLAG})`);}
  const source = await readFile(join(input.cwd, match.file), 'utf8');
  const proposed = proposeFix(match, source);
  if (proposed === undefined || proposed.safe !== true) {fail(`fix --finding has no safe fix (${SAST_PARITY_FLAG})`);}
  await assertWritable(input.cwd, input.force);
  await writeFile(join(input.cwd, match.file), applyUnifiedDiff(source, proposed.diff), 'utf8');
  return { file: match.file };
}
