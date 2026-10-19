import { cp, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import type { Finding } from '../../../../src/core/finding.js';

const fixture = join(import.meta.dirname, '../../../fixtures/upgrade-plan-app');

describe('phase 55 observed reach scan', () => {
  const dirs: string[] = [];

  afterEach(async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_OBSERVED_REACH;
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('ignores the file unless the flag is set, and a missing or unreadable file changes nothing', async () => {
    const app = await copyApp();
    const plain = await scan({ cwd: app, modules: ['deps'], offline: true });
    await writeObserved(app, { packages: { held: ['.'] } });
    const ignored = await scan({ cwd: app, modules: ['deps'], offline: true });
    expect(keys(ignored)).toEqual(keys(plain));
    expect(ignored.findings.every((finding) => finding.observedReach === undefined)).toBe(true);

    process.env.FULLSHIELD_EXPERIMENTAL_OBSERVED_REACH = '1';
    await rm(join(app, '.fullshield'), { recursive: true, force: true });
    const missing = await scan({ cwd: app, modules: ['deps'], offline: true });
    expect(keys(missing)).toEqual(keys(plain));
    expect(missing.findings.every((finding) => finding.observedReach === undefined)).toBe(true);
    expect(reachOf(missing, 'held')).toBe(reachOf(plain, 'held'));

    await writeObserved(app, {});
    await writeFile(join(app, '.fullshield', 'observed-reach.json'), '{', 'utf8');
    const broken = await scan({ cwd: app, modules: ['deps'], offline: true });
    expect(keys(broken)).toEqual(keys(plain));
    expect(broken.findings.every((finding) => finding.observedReach === undefined)).toBe(true);
  });

  it('confirms a loaded package and records a downgrade without changing the finding key', async () => {
    const app = await copyApp();
    const plain = await scan({ cwd: app, modules: ['deps'], offline: true });
    await writeObserved(app, { packages: { held: ['.'] } });
    process.env.FULLSHIELD_EXPERIMENTAL_OBSERVED_REACH = '1';
    const result = await scan({ cwd: app, modules: ['deps'], offline: true });
    expect(keys(result)).toEqual(keys(plain));

    const held = result.findings.find((finding) => finding.snippet?.startsWith('held@'));
    expect(held?.observedReach).toBe('confirmed');
    expect(held?.reachability).toBe('reachable');

    const express = result.findings.find((finding) => finding.snippet?.startsWith('express@'));
    const before = plain.findings.find((finding) => finding.snippet?.startsWith('express@'));
    expect(express?.observedReach).toBe('downgraded');
    expect(express?.reachability).toBe(before?.reachability);
    expect(express?.severity).toBe(before?.severity);
  });

  async function copyApp(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), 'fs-observed-scan-'));
    dirs.push(dir);
    await cp(fixture, dir, { recursive: true });
    return dir;
  }
});

async function writeObserved(cwd: string, body: unknown): Promise<void> {
  const { mkdir } = await import('node:fs/promises');
  await mkdir(join(cwd, '.fullshield'), { recursive: true });
  await writeFile(join(cwd, '.fullshield', 'observed-reach.json'), `${JSON.stringify(body)}\n`);
}

function keys(result: { findings: Finding[] }): string[] {
  return result.findings.map((f) => `${f.ruleId}\t${f.file ?? ''}\t${f.line ?? ''}\t${f.severity}`).sort();
}

function reachOf(result: { findings: Finding[] }, name: string): string | undefined {
  return result.findings.find((finding) => finding.snippet?.startsWith(`${name}@`))?.reachability;
}
