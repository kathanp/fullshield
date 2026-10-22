import { readFileSync } from 'node:fs';
import { mkdtemp, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { advisoryCacheAge, enabled, FLAG } from '../../../src/phases/p380.js';

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('phase 380 cache age', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(advisoryCacheAge(null, Date.now())).toEqual([]);
  });

  it('emits nothing for a cache touched 1 hour ago', async () => {
    process.env[FLAG] = '1';
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-p380-'));
    dirs.push(dir);
    const file = join(dir, 'osv.json');
    await writeFile(file, '{}');
    const now = Date.now();
    const touched = new Date(now - 60 * 60 * 1000);
    await utimes(file, touched, touched);
    expect(advisoryCacheAge(dir, now)).toEqual([]);
  });

  it('emits info with the hours for a cache touched 72 hours ago', async () => {
    process.env[FLAG] = '1';
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-p380-'));
    dirs.push(dir);
    const file = join(dir, 'osv.json');
    await writeFile(file, '{}');
    const now = Date.now();
    const touched = new Date(now - 72 * 60 * 60 * 1000);
    await utimes(file, touched, touched);
    const findings = advisoryCacheAge(dir, now);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('info');
    expect(findings[0]?.age).toBe(72);
    expect(findings[0]?.message).toContain(findings[0]?.now ?? '');
    expect(findings[0]?.message).toContain(findings[0]?.cacheMtime ?? '');
  });

  it('emits info with a null age when the cache is missing and does not use HTTP', () => {
    process.env[FLAG] = '1';
    const findings = advisoryCacheAge(null, Date.parse('2026-01-01T00:00:00.000Z'));
    expect(findings[0]?.age).toBeNull();
    const source = readFileSync(new URL('../../../src/phases/p380.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('node:http');
    expect(source).not.toContain('node:https');
  });
});
