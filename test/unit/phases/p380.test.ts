import { mkdirSync, readFileSync, symlinkSync } from 'node:fs';
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

  it('reports a missing directory, an empty directory, and a broken symlink', async () => {
    process.env[FLAG] = '1';
    const now = Date.parse('2026-01-01T00:00:00.000Z');
    const missing = advisoryCacheAge(join(tmpdir(), 'fullshield-p380-missing-cache'), now);
    expect(missing[0]?.age).toBeNull();
    const empty = await mkdtemp(join(tmpdir(), 'fullshield-p380-'));
    dirs.push(empty);
    expect(advisoryCacheAge(empty, now)[0]?.cacheMtime).toBeNull();
    const broken = await mkdtemp(join(tmpdir(), 'fullshield-p380-'));
    dirs.push(broken);
    symlinkSync(join(broken, 'missing'), join(broken, 'broken'));
    expect(advisoryCacheAge(broken, now)[0]?.age).toBeNull();
    delete process.env[FLAG];
  });

  it('uses the newest file under a nested directory', async () => {
    process.env[FLAG] = '1';
    const now = Date.now();
    const older = new Date(now - 100 * 60 * 60 * 1000);
    const newer = new Date(now - 80 * 60 * 60 * 1000);
    const first = await mkdtemp(join(tmpdir(), 'fullshield-p380-'));
    dirs.push(first);
    const oldFile = join(first, 'a.txt');
    await writeFile(oldFile, '{}');
    await utimes(oldFile, older, older);
    const nested = join(first, 'b-sub');
    mkdirSync(nested);
    const nestedFile = join(nested, 'new.txt');
    await writeFile(nestedFile, '{}');
    await utimes(nestedFile, newer, newer);
    expect(advisoryCacheAge(first, now)[0]?.age).toBe(80);
    const second = await mkdtemp(join(tmpdir(), 'fullshield-p380-'));
    dirs.push(second);
    const emptyNested = join(second, 'a-sub');
    mkdirSync(emptyNested);
    const fresh = join(second, 'b.txt');
    await writeFile(fresh, '{}');
    await utimes(fresh, newer, newer);
    expect(advisoryCacheAge(second, now)[0]?.age).toBe(80);
    const third = await mkdtemp(join(tmpdir(), 'fullshield-p380-'));
    dirs.push(third);
    const recent = join(third, 'a.txt');
    await writeFile(recent, '{}');
    await utimes(recent, new Date(now - 60 * 60 * 1000), new Date(now - 60 * 60 * 1000));
    const oldNested = join(third, 'b-sub');
    mkdirSync(oldNested);
    const stale = join(oldNested, 'old.txt');
    await writeFile(stale, '{}');
    await utimes(stale, older, older);
    expect(advisoryCacheAge(third, now)).toEqual([]);
    delete process.env[FLAG];
  });
});
