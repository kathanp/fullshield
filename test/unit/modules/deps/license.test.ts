import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { isCopyleftLicense, scanCopyleftLicenses } from '../../../../src/modules/deps/license.js';
import { historyCommitLimit } from '../../../../src/modules/secrets/history.js';

describe('copyleft licenses', () => {
  it('matches GPL and AGPL and ignores MIT and LGPL', () => {
    expect(isCopyleftLicense('GPL-3.0')).toBe(true);
    expect(isCopyleftLicense('AGPL-3.0-only')).toBe(true);
    expect(isCopyleftLicense('MIT')).toBe(false);
    expect(isCopyleftLicense('LGPL-3.0')).toBe(false);
  });

  it('reads an installed package.json and skips a missing tree', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-license-'));
    await writeFile(join(dir, 'package.json'), JSON.stringify({ dependencies: { left: '1.0.0', mit: '1.0.0' } }));
    await mkdir(join(dir, 'node_modules', 'left'), { recursive: true });
    await mkdir(join(dir, 'node_modules', 'mit'), { recursive: true });
    await writeFile(join(dir, 'node_modules', 'left', 'package.json'), JSON.stringify({ license: 'GPL-2.0' }));
    await writeFile(join(dir, 'node_modules', 'mit', 'package.json'), JSON.stringify({ license: 'MIT' }));
    const findings = await scanCopyleftLicenses(dir);
    expect(findings.map((finding) => finding.snippet)).toEqual(['left GPL-2.0']);
    const empty = await mkdtemp(join(tmpdir(), 'fullshield-license-empty-'));
    await writeFile(join(empty, 'package.json'), JSON.stringify({ dependencies: { gone: '1.0.0' } }));
    expect(await scanCopyleftLicenses(empty)).toEqual([]);
  });
});

describe('history commit cap', () => {
  it('defaults to 500 and clamps the override', () => {
    expect(historyCommitLimit(undefined)).toBe(500);
    expect(historyCommitLimit('20')).toBe(20);
    expect(historyCommitLimit('0')).toBe(500);
    expect(historyCommitLimit('9000')).toBe(5000);
  });
});
