import { mkdtemp, readFile, rm, symlink, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawn } from 'node:child_process';

import { scan } from '../core/engine.js';
import { applyUnifiedDiff, proposeFix } from './patches.js';

export type FixProof = 'fixed' | 'fixed-tests-fail' | 'not-fixed';

export interface TempVerifyInput {
  cwd: string;
  file: string;
  diff: string;
  ruleId: string;
  runTests?: boolean;
}

async function npmTest(dir: string): Promise<boolean> {
  return await new Promise((resolve) => {
    const child = spawn('npm', ['test', '--silent'], { cwd: dir, stdio: 'ignore' });
    const timer = setTimeout(() => {
      child.kill();
      resolve(false);
    }, 30_000);
    child.once('exit', (code) => {
      clearTimeout(timer);
      resolve(code === 0);
    });
    child.once('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

export async function proveFixes(cwd: string): Promise<Array<{ ruleId: string; status: FixProof }>> {
  const result = await scan({ cwd, offline: true });
  const rows: Array<{ ruleId: string; status: FixProof }> = [];
  for (const finding of result.findings.slice(0, 20)) {
    if (finding.file === undefined) {continue;}
    const source = await readFile(join(cwd, finding.file), 'utf8').catch(() => undefined);
    if (source === undefined) {continue;}
    const proposal = proposeFix(finding, source);
    if (proposal === undefined) {continue;}
    const status = await verifyFixInCopy({
      cwd,
      file: finding.file,
      diff: proposal.diff,
      ruleId: finding.ruleId,
    });
    rows.push({ ruleId: finding.ruleId, status });
  }
  return rows;
}

async function copyPackage(cwd: string, dir: string): Promise<boolean> {
  try {
    const text = await readFile(join(cwd, 'package.json'), 'utf8');
    await writeFile(join(dir, 'package.json'), text, 'utf8');
    await symlink(join(cwd, 'node_modules'), join(dir, 'node_modules'), 'dir').catch(() => undefined);
    const parsed = JSON.parse(text) as { scripts?: { test?: unknown } };
    return typeof parsed.scripts?.test === 'string';
  } catch {
    return false;
  }
}

/** Applies the diff in a temp copy. The original file is not written. */
export async function verifyFixInCopy(input: TempVerifyInput): Promise<FixProof> {
  const rel = input.file.split('\\').join('/');
  const original = await readFile(join(input.cwd, rel), 'utf8');
  const dir = await mkdtemp(join(tmpdir(), 'fs-fix-'));
  try {
    const target = join(dir, rel);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, applyUnifiedDiff(original, input.diff), 'utf8');
    const hasTests = await copyPackage(input.cwd, dir);
    const result = await scan({ cwd: dir, offline: true, modules: ['sast', 'secrets', 'config'] });
    const still = result.findings.some((finding) => finding.ruleId === input.ruleId);
    if (still) {return 'not-fixed';}
    if (input.runTests === false || !hasTests) {return 'fixed';}
    const ok = await npmTest(dir);
    return ok ? 'fixed' : 'fixed-tests-fail';
  } finally {
    const after = await readFile(join(input.cwd, rel), 'utf8');
    if (after !== original) {
      throw new Error('verify touched the working tree');
    }
    await rm(dir, { recursive: true, force: true });
  }
}
