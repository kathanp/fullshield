import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

import { scan } from '../core/engine.js';
import type { Finding } from '../core/finding.js';
import { unifiedDiff } from '../fixer/diff.js';
import { proposeFix } from '../fixer/patches.js';
import { fixtureFix } from './fixtures.js';
import { asFix } from './parse.js';
import type { AiClient } from './provider.js';

export interface AiFixResult {
  accepted: boolean;
  attempts: number;
  diff: string;
  file?: string;
}

async function verifyPatch(
  cwd: string,
  original: Awaited<ReturnType<typeof scan>>,
  file: string,
  after: string,
): Promise<{ ok: boolean; diff: string }> {
  const tmp = await mkdtemp(join(tmpdir(), 'fullshield-ai-fix-'));
  try {
    cpSync(cwd, tmp, { recursive: true });
    const dest = join(tmp, file);
    if (!existsSync(dirname(dest))) {mkdirSync(dirname(dest), { recursive: true });}
    const before = await readFile(join(cwd, file), 'utf8').catch(() => '');
    await writeFile(dest, after, 'utf8');
    const diff = unifiedDiff(file, before, after);
    const again = await scan({ cwd: tmp, offline: true });
    const targetIds = new Set(original.findings.filter((f) => f.file === file).map((f) => f.ruleId));
    const gone = [...targetIds].every((id) => !again.findings.some((f) => f.ruleId === id && f.file === file));
    const newIds = new Set(again.findings.map((f) => f.ruleId));
    const oldIds = new Set(original.findings.map((f) => f.ruleId));
    const added = [...newIds].filter((id) => !oldIds.has(id));
    if (!gone || added.length > 0) {return { ok: false, diff };}
    const pkg = join(tmp, 'package.json');
    if (existsSync(pkg)) {
      const parsed = JSON.parse(await readFile(pkg, 'utf8')) as { scripts?: { test?: string } };
      if (parsed.scripts?.test !== undefined) {
        const test = spawnSync('npm', ['test'], { cwd: tmp, encoding: 'utf8' });
        if (test.status !== 0) {return { ok: false, diff };}
      }
    }
    return { ok: true, diff };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Draft a patch for findings that have no rule-based fix. Apply in a temp
 * copy, rescan, optionally run tests. Keep only if the finding disappears
 * and no new findings appear. Max 2 attempts. Never writes the user's tree.
 */
export async function runAiFix(options: {
  cwd: string;
  client: AiClient;
}): Promise<AiFixResult> {
  const result = await scan({ cwd: options.cwd, offline: true });
  const target = result.findings.find((f) => {
    if (f.file === undefined) {return false;}
    return proposeFix(f, '') === undefined;
  });
  if (target === undefined || target.file === undefined) {
    return { accepted: false, attempts: 0, diff: '' };
  }

  let attempts = 0;
  let lastDiff = '';
  let lastFile = target.file;
  while (attempts < 2) {
    attempts += 1;
    const res = await options.client.complete({
      mode: 'fix',
      prompt: `${target.ruleId}\n${target.file}\n${target.message}`,
    });
    if (res === null) {break;}

    const patch = options.client.useFixtures ? fixtureFix(target.ruleId) : asFix(res.json);
    if (patch === undefined) {continue;}
    lastFile = patch.file;
    const checked = await verifyPatch(options.cwd, result, patch.file, patch.after);
    lastDiff = checked.diff;
    if (checked.ok) {return { accepted: true, attempts, diff: lastDiff, file: patch.file };}
  }
  return { accepted: false, attempts, diff: lastDiff, file: lastFile };
}

export function findingsWithoutRuleFix(findings: readonly Finding[], sources: Record<string, string>): Finding[] {
  return findings.filter((f) => {
    if (f.file === undefined) {return true;}
    return proposeFix(f, sources[f.file] ?? '') === undefined;
  });
}
