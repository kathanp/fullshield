import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { BYTES_NOT_CHECKED, enabled, FLAG, httpClientsConstructed, sriFindings, sriFromFile } from '../../../src/phases/p374.js';

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('phase 374 SRI grammar', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(sriFindings('sha1-aaaa')).toEqual([]);
  });

  it('emits nothing for a well formed sha512 token', () => {
    process.env[FLAG] = '1';
    expect(sriFindings('sha512-aaaaaaaa')).toEqual([]);
  });

  it('reports sha1 at low and says the bytes were not checked', () => {
    process.env[FLAG] = '1';
    const findings = sriFindings('sha1-aaaaaaaa');
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.message).toContain(BYTES_NOT_CHECKED);
  });

  it('reports a broken attribute at medium', () => {
    process.env[FLAG] = '1';
    expect(sriFindings('not-a-token!!!')[0]?.severity).toBe('medium');
  });

  it('compares a local file and constructs no HTTP client', async () => {
    process.env[FLAG] = '1';
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-p374-'));
    dirs.push(dir);
    const file = join(dir, 'app.js');
    await writeFile(file, 'alert(1)\n');
    const digest = createHash('sha512').update(readFileSync(file)).digest('base64');
    expect(sriFromFile(`sha512-${digest}`, file)).toEqual([]);
    expect(sriFromFile('sha512-aaaaaaaa', file)[0]?.severity).toBe('medium');
    expect(httpClientsConstructed).toBe(0);
    const source = readFileSync(new URL('../../../src/phases/p374.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('node:http');
    expect(source).not.toContain('node:https');
  });
});
