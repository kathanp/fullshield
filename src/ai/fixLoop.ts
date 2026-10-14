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
import type { AiClient } from './provider.js';

export interface AiFixResult {
  accepted: boolean;
  attempts: number;
  diff: string;
  file?: string;
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
    if (f.file === undefined) return false;
    try {
      const source = '';
      return proposeFix(f, source) === undefined && fixtureFix(f.ruleId) !== undefined;
    } catch {
      return fixtureFix(f.ruleId) !== undefined;
    }
  });
  if (target === undefined) {
    return { accepted: false, attempts: 0, diff: '' };
  }
  const recorded = fixtureFix(target.ruleId);
  if (recorded === undefined || target.file === undefined) {
    return { accepted: false, attempts: 0, diff: '' };
  }

  let attempts = 0;
  let lastDiff = '';
  while (attempts < 2) {
    attempts += 1;
    const res = await options.client.complete({
      mode: 'fix',
      prompt: `${target.ruleId}\n${target.file}`,
    });
    if (res === null) break;

    const tmp = await mkdtemp(join(tmpdir(), 'fullshield-ai-fix-'));
    try {
      cpSync(options.cwd, tmp, { recursive: true });
      const dest = join(tmp, recorded.file);
      if (!existsSync(dirname(dest))) mkdirSync(dirname(dest), { recursive: true });
      const before = await readFile(join(options.cwd, recorded.file), 'utf8').catch(() => '');
      await writeFile(dest, recorded.after, 'utf8');
      lastDiff = unifiedDiff(recorded.file, before, recorded.after);

      const again = await scan({ cwd: tmp, offline: true });
      const gone = !again.findings.some((f) => f.ruleId === target.ruleId);
      const newIds = new Set(again.findings.map((f) => f.ruleId));
      const oldIds = new Set(result.findings.map((f) => f.ruleId));
      const added = [...newIds].filter((id) => !oldIds.has(id));
      if (!gone || added.length > 0) continue;

      const pkg = join(tmp, 'package.json');
      if (existsSync(pkg)) {
        const parsed = JSON.parse(await readFile(pkg, 'utf8')) as { scripts?: { test?: string } };
        if (parsed.scripts?.test !== undefined) {
          const test = spawnSync('npm', ['test'], { cwd: tmp, encoding: 'utf8' });
          if (test.status !== 0) continue;
        }
      }
      return { accepted: true, attempts, diff: lastDiff, file: recorded.file };
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }
  return { accepted: false, attempts, diff: lastDiff, file: recorded.file };
}

export function findingsWithoutRuleFix(findings: readonly Finding[], sources: Record<string, string>): Finding[] {
  return findings.filter((f) => {
    if (f.file === undefined) return true;
    return proposeFix(f, sources[f.file] ?? '') === undefined;
  });
}
