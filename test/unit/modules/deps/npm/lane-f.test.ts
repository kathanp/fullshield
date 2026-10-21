import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { POPULAR_PACKAGES } from '../../../../../src/modules/deps/popular.js';
import { findTyposquats } from '../../../../../src/modules/deps/typosquat.js';
import { laneFindings as laneAFindings } from '../../../../../src/modules/deps/npm/lane-a.js';
import { laneFindings, laneRows } from '../../../../../src/modules/deps/npm/lane-f.js';
import type { NpmDepthInput } from '../../../../../src/modules/deps/npm/types.js';
import { registryCachePath } from '../../../../../src/provenance/index.js';

const FLAGS = [
  'NPM_SCOPE_TYPO',
  'NPM_HOMOGLYPH',
  'NPM_BIDI',
  'NPM_MIXEDSCRIPT',
  'NPM_SEPARATOR',
  'NPM_REPEAT',
  'NPM_SUFFIX',
  'NPM_SCOPE_NEW',
  'NPM_SCOPE_SYNTAX',
  'NPM_TYPES',
  'NPM_DEPRECATED_REPLACE',
  'NPM_TYPO_TRANSITIVE',
  'NPM_NAME_LENGTH',
  'NPM_NAME_CASE',
  'NPM_NAME_ENCODED',
  'NPM_ALIAS_SQUAT',
  'NPM_SELFNAME',
  'NPM_WORKSPACE_NAME',
  'NPM_POPULAR_LIST',
  'NPM_DISTANCE2',
] as const;

const POPULAR_HASH = '34bc3df7f4d59d7462ef127119e1ca446eaf2a725874dd8a5e61fc8f600d934c';
const PACKAGE_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const LEGACY_UNGRAMMATICAL = new Set(['node:test', 'uvu/assert']);

const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function setFlag(name: string): void {
  process.env[`FULLSHIELD_EXPERIMENTAL_${name}`] = '1';
}

function setAll(): void {
  for (const name of FLAGS) {setFlag(name);}
}

function ids(findings: { ruleId: string }[]): string[] {
  return findings.map((finding) => finding.ruleId).sort();
}

function depth(manifest: unknown, lock?: unknown, extra?: Partial<NpmDepthInput>): NpmDepthInput {
  const files = ['package.json'];
  const lockTexts: Record<string, string> = {};
  if (lock !== undefined) {
    files.push('package-lock.json');
    lockTexts['package-lock.json'] = JSON.stringify(lock);
  }
  return {
    cwd: extra?.cwd ?? process.cwd(),
    files: extra?.files ?? files,
    manifestRaw: extra?.manifestRaw ?? JSON.stringify(manifest),
    lockTexts: extra?.lockTexts ?? lockTexts,
    cacheDir: extra?.cacheDir ?? join(process.cwd(), 'missing-lane-f-cache'),
    offline: extra?.offline ?? true,
  };
}

function lockWith(names: readonly string[], extra: Record<string, unknown> = {}): unknown {
  const packages: Record<string, unknown> = { '': { name: 'app' } };
  for (const name of names) {
    packages[`node_modules/${name}`] = { version: '1.0.0', ...extra };
  }
  return { name: 'app', lockfileVersion: 3, packages };
}

async function tempCache(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fullshield-lane-f-'));
  dirs.push(dir);
  await mkdir(join(dir, 'registry'), { recursive: true });
  return dir;
}

function levenshtein(a: string, b: string): number {
  const rows: number[][] = [];
  for (let i = 0; i <= a.length; i += 1) {rows.push(new Array<number>(b.length + 1).fill(0));}
  for (let i = 0; i <= a.length; i += 1) {
    const row = rows[i];
    if (row !== undefined) {row[0] = i;}
  }
  const header = rows[0];
  if (header !== undefined) {
    for (let j = 0; j <= b.length; j += 1) {header[j] = j;}
  }
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const row = rows[i];
      const prev = rows[i - 1];
      if (row === undefined || prev === undefined) {continue;}
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      row[j] = Math.min((prev[j] ?? 0) + 1, (row[j - 1] ?? 0) + 1, (prev[j - 1] ?? 0) + cost);
    }
  }
  return rows[a.length]?.[b.length] ?? 0;
}

describe('npm lane F package names', () => {
  it('emits nothing when none of the lane flags are set', async () => {
    const findings = await laneFindings(depth({
      name: 'app',
      dependencies: { '\u0435xpress': '1.0.0', 'socket_io.client': '1.0.0' },
    }));
    expect(findings).toEqual([]);
  });

  it('lists every rule id from the lane source in laneRows', () => {
    const src = readFileSync(join(process.cwd(), 'src', 'modules', 'deps', 'npm', 'lane-f.ts'), 'utf8');
    const mentioned = [...src.matchAll(/DEPS-[A-Z0-9-]+/g)].map((match) => match[0]);
    const rowIds = laneRows.map((row) => row.ruleId);
    expect([...new Set(mentioned)].sort()).toEqual([...rowIds].sort());
    for (const row of laneRows) {
      expect(existsSync(join(process.cwd(), 'rules', `${row.ruleId}.md`))).toBe(true);
    }
  });

  it('flags a devDependency scope that is one edit from a popular scope', async () => {
    setFlag('NPM_SCOPE_TYPO');
    const findings = await laneFindings(depth({
      name: 'app',
      devDependencies: { '@babl/core': '1.0.0' },
    }));
    expect(ids(findings)).toEqual(['DEPS-SCOPE-TYPO-001']);
    expect(findings[0]).toMatchObject({ severity: 'medium', confidence: 'medium', file: 'package.json' });
    expect(findings[0]?.message).toMatch(/babel/);
  });

  it('does not flag the real scope, a basename that is not in that scope, an unscoped name, or a peer', async () => {
    setFlag('NPM_SCOPE_TYPO');
    const real = await laneFindings(depth({ name: 'app', dependencies: { '@babel/core': '1.0.0' } }));
    const other = await laneFindings(depth({ name: 'app', dependencies: { '@babl/not-on-list': '1.0.0' } }));
    const unscoped = await laneFindings(depth({ name: 'app', dependencies: { express: '1.0.0' } }));
    const peer = await laneFindings(depth({ name: 'app', peerDependencies: { '@babl/core': '1.0.0' } }));
    expect(real).toEqual([]);
    expect(other).toEqual([]);
    expect(unscoped).toEqual([]);
    expect(peer).toEqual([]);
  });

  it('flags a non-ASCII name whose confusable letters spell a popular package', async () => {
    setFlag('NPM_HOMOGLYPH');
    setFlag('NPM_MIXEDSCRIPT');
    const findings = await laneFindings(depth({ name: 'app', dependencies: { '\u0435xpress': '1.0.0' } }));
    expect(ids(findings)).toEqual(['DEPS-HOMOGLYPH-001']);
    expect(findings[0]).toMatchObject({ severity: 'high' });
    expect(findings[0]?.message).toMatch(/express/);
  });

  it('flags a non-ASCII name whose NFKC form is a popular package', async () => {
    setFlag('NPM_HOMOGLYPH');
    const findings = await laneFindings(depth({ name: 'app', dependencies: { '\uFF45xpress': '1.0.0' } }));
    expect(ids(findings)).toEqual(['DEPS-HOMOGLYPH-001']);
    expect(findings[0]?.message).toMatch(/express/);
  });

  it('does not flag an ASCII name or a non-ASCII name that does not map to a popular package', async () => {
    setFlag('NPM_HOMOGLYPH');
    setFlag('NPM_MIXEDSCRIPT');
    const ascii = await laneFindings(depth({ name: 'app', dependencies: { express: '1.0.0' } }));
    const other = await laneFindings(depth({
      name: 'app',
      dependencies: { '\u043f\u0440\u0438\u0432\u0435\u0442': '1.0.0' },
    }));
    expect(ascii).toEqual([]);
    expect(other).toEqual([]);
  });

  it('flags a bidi or zero-width character in a dependency name', async () => {
    setFlag('NPM_BIDI');
    const findings = await laneFindings(depth({ name: 'app', dependencies: { 'express\u202E': '1.0.0' } }));
    expect(ids(findings)).toEqual(['DEPS-BIDI-001']);
    expect(findings[0]).toMatchObject({ severity: 'critical' });
  });

  it('does not flag an ASCII name for bidi', async () => {
    setFlag('NPM_BIDI');
    expect(await laneFindings(depth({ name: 'app', dependencies: { express: '1.0.0' } }))).toEqual([]);
  });

  it('flags a name that mixes Latin with Cyrillic when it is not a homoglyph', async () => {
    setFlag('NPM_MIXEDSCRIPT');
    setFlag('NPM_HOMOGLYPH');
    const findings = await laneFindings(depth({ name: 'app', dependencies: { 'expres\u0441': '1.0.0' } }));
    expect(ids(findings)).toEqual(['DEPS-MIXEDSCRIPT-001']);
    expect(findings[0]).toMatchObject({ severity: 'high' });
  });

  it('does not flag Latin-only or Cyrillic-only names for mixed script', async () => {
    setFlag('NPM_MIXEDSCRIPT');
    setFlag('NPM_HOMOGLYPH');
    const latin = await laneFindings(depth({ name: 'app', dependencies: { express: '1.0.0' } }));
    const cyrillic = await laneFindings(depth({
      name: 'app',
      dependencies: { '\u043f\u0440\u0438\u0432\u0435\u0442': '1.0.0' },
    }));
    expect(latin).toEqual([]);
    expect(cyrillic).toEqual([]);
  });

  it('flags a direct name that matches a popular name after separator normalization at distance greater than 1', async () => {
    setFlag('NPM_SEPARATOR');
    const findings = await laneFindings(depth({ name: 'app', dependencies: { 'socket_io.client': '1.0.0' } }));
    expect(ids(findings)).toEqual(['DEPS-SEPARATOR-001']);
    expect(findings[0]).toMatchObject({ severity: 'medium' });
    expect(findings[0]?.message).toMatch(/socket\.io-client/);
    expect(levenshtein('socket_io.client', 'socket.io-client')).toBe(2);
  });

  it('does not flag the exact popular name, a one-letter difference, or a distance-1 separator twin', async () => {
    setFlag('NPM_SEPARATOR');
    const exact = await laneFindings(depth({ name: 'app', dependencies: { 'socket.io-client': '1.0.0' } }));
    const letter = await laneFindings(depth({ name: 'app', dependencies: { 'socket.io-clien': '1.0.0' } }));
    const oneEdit = await laneFindings(depth({ name: 'app', dependencies: { 'react.dom': '1.0.0' } }));
    expect(exact).toEqual([]);
    expect(letter).toEqual([]);
    expect(oneEdit).toEqual([]);
    expect(findTyposquats(
      [{ name: 'react.dom', version: '1.0.0', path: 'node_modules/react.dom' }],
      { directNames: new Set(['react.dom']) },
    ).length).toBeGreaterThan(0);
  });

  it('flags a repeated popular basename and ignores the package itself and a distance-1 name', async () => {
    setFlag('NPM_REPEAT');
    const hit = await laneFindings(depth({ name: 'app', dependencies: { 'express-express': '1.0.0' } }));
    const itself = await laneFindings(depth({ name: 'app', dependencies: { express: '1.0.0' } }));
    const oneEdit = await laneFindings(depth({ name: 'app', dependencies: { expresss: '1.0.0' } }));
    expect(ids(hit)).toEqual(['DEPS-REPEAT-001']);
    expect(hit[0]).toMatchObject({ severity: 'medium' });
    expect(itself).toEqual([]);
    expect(oneEdit).toEqual([]);
  });

  it('flags an optional dependency that adds a listed suffix, with low confidence', async () => {
    setFlag('NPM_SUFFIX');
    const findings = await laneFindings(depth({
      name: 'app',
      optionalDependencies: { 'express-js': '1.0.0' },
    }));
    expect(ids(findings)).toEqual(['DEPS-SUFFIX-001']);
    expect(findings[0]).toMatchObject({ severity: 'low', confidence: 'low' });
    expect(findings[0]?.message.toLowerCase()).toMatch(/confirm/);
    expect(findings[0]?.message.toLowerCase()).not.toMatch(/malicious/);
  });

  it('does not flag the popular name or a suffix outside the list', async () => {
    setFlag('NPM_SUFFIX');
    const exact = await laneFindings(depth({ name: 'app', dependencies: { express: '1.0.0' } }));
    const other = await laneFindings(depth({ name: 'app', dependencies: { 'express-sdk': '1.0.0' } }));
    expect(exact).toEqual([]);
    expect(other).toEqual([]);
  });

  it('flags a new scope whose earliest packument version is younger than 7 days', async () => {
    setFlag('NPM_SCOPE_NEW');
    const cacheDir = await tempCache();
    const young = new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString();
    await writeFile(registryCachePath(cacheDir, '@fresh/pkg'), JSON.stringify({
      packument: { time: { created: young, '1.0.0': young }, versions: { '1.0.0': {} } },
    }));
    const findings = await laneFindings(depth(
      { name: 'app', dependencies: { '@fresh/pkg': '1.0.0' } },
      undefined,
      { cacheDir },
    ));
    expect(ids(findings)).toEqual(['DEPS-SCOPE-NEW-001']);
    expect(findings[0]).toMatchObject({ severity: 'medium' });
  });

  it('does not flag an older first publish, the project scope, or a missing packument', async () => {
    setFlag('NPM_SCOPE_NEW');
    const cacheDir = await tempCache();
    const old = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    const young = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString();
    await writeFile(registryCachePath(cacheDir, '@fresh/pkg'), JSON.stringify({
      packument: { time: { '1.0.0': old }, versions: { '1.0.0': {} } },
    }));
    await writeFile(registryCachePath(cacheDir, '@fresh/own'), JSON.stringify({
      packument: { time: { '1.0.0': young }, versions: { '1.0.0': {} } },
    }));
    const older = await laneFindings(depth(
      { name: 'app', dependencies: { '@fresh/pkg': '1.0.0' } },
      undefined,
      { cacheDir },
    ));
    const own = await laneFindings(depth(
      { name: '@fresh/app', dependencies: { '@fresh/own': '1.0.0' } },
      undefined,
      { cacheDir },
    ));
    const missing = await laneFindings(depth(
      { name: 'app', dependencies: { '@fresh/absent': '1.0.0' } },
      undefined,
      { cacheDir },
    ));
    expect(older).toEqual([]);
    expect(own).toEqual([]);
    expect(missing).toEqual([]);
  });

  it('flags a missing slash and a second slash in a scoped name', async () => {
    setFlag('NPM_SCOPE_SYNTAX');
    const missing = await laneFindings(depth({ name: 'app', dependencies: { '@noslash': '1.0.0' } }));
    const extra = await laneFindings(depth({ name: 'app', dependencies: { '@scope/name/extra': '1.0.0' } }));
    const ok = await laneFindings(depth({ name: 'app', dependencies: { '@scope/name': '1.0.0' } }));
    expect(ids(missing)).toEqual(['DEPS-SCOPE-SYNTAX-001']);
    expect(ids(extra)).toEqual(['DEPS-SCOPE-SYNTAX-001']);
    expect(missing[0]).toMatchObject({ severity: 'high' });
    expect(ok).toEqual([]);
  });

  it('flags @types for a package whose packument already has types', async () => {
    setFlag('NPM_TYPES');
    const cacheDir = await tempCache();
    await writeFile(registryCachePath(cacheDir, 'ms'), JSON.stringify({
      packument: { versions: { '2.1.3': { types: 'index.d.ts' } } },
    }));
    const findings = await laneFindings(depth(
      { name: 'app', dependencies: { ms: '2.1.3', '@types/ms': '2.1.3' } },
      undefined,
      { cacheDir },
    ));
    expect(ids(findings)).toEqual(['DEPS-TYPES-001']);
    expect(findings[0]).toMatchObject({ severity: 'info', snippet: 'ms' });
  });

  it('does not flag @types when the packument has neither field or is missing', async () => {
    setFlag('NPM_TYPES');
    const cacheDir = await tempCache();
    await writeFile(registryCachePath(cacheDir, 'ms'), JSON.stringify({
      packument: { versions: { '2.1.3': { name: 'ms' } } },
    }));
    const neither = await laneFindings(depth(
      { name: 'app', dependencies: { ms: '2.1.3', '@types/ms': '2.1.3' } },
      undefined,
      { cacheDir },
    ));
    const missing = await laneFindings(depth(
      { name: 'app', dependencies: { debug: '1.0.0', '@types/debug': '1.0.0' } },
      undefined,
      { cacheDir },
    ));
    expect(neither).toEqual([]);
    expect(missing).toEqual([]);
  });

  it('flags a deprecation notice that names a package the project does not depend on', async () => {
    setFlag('NPM_DEPRECATED_REPLACE');
    const use = await laneFindings(depth(
      { name: 'app', dependencies: { 'left-pad': '1.0.0' } },
      {
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/left-pad': { version: '1.0.0', deprecated: 'use lodash instead' },
        },
      },
    ));
    const replaced = await laneFindings(depth(
      { name: 'app', dependencies: { oldlib: '1.0.0' } },
      {
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/oldlib': { version: '1.0.0', deprecated: 'replaced by chalk' },
        },
      },
    ));
    expect(ids(use)).toEqual(['DEPS-DEPRECATED-REPLACE-001']);
    expect(use[0]).toMatchObject({ severity: 'info' });
    expect(use[0]?.message).toMatch(/lodash/);
    expect(replaced[0]?.message).toMatch(/chalk/);
  });

  it('does not invent a replacement or flag one that is already direct', async () => {
    setFlag('NPM_DEPRECATED_REPLACE');
    const unnamed = await laneFindings(depth(
      { name: 'app', dependencies: { oldlib: '1.0.0' } },
      {
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/oldlib': { version: '1.0.0', deprecated: 'no longer maintained' },
        },
      },
    ));
    const present = await laneFindings(depth(
      { name: 'app', dependencies: { oldlib: '1.0.0', lodash: '4.0.0' } },
      {
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/oldlib': { version: '1.0.0', deprecated: 'use lodash instead' },
        },
      },
    ));
    expect(unnamed).toEqual([]);
    expect(present).toEqual([]);
  });

  it('applies name checks to a transitive package as one informational row', async () => {
    setFlag('NPM_TYPO_TRANSITIVE');
    setFlag('NPM_SEPARATOR');
    const findings = await laneFindings(depth(
      { name: 'app', dependencies: { express: '4.0.0' } },
      {
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { express: '4.0.0' } },
          'node_modules/express': { version: '4.0.0' },
          'node_modules/express/node_modules/socket_io.client': { version: '1.0.0' },
        },
      },
    ));
    expect(ids(findings)).toEqual(['DEPS-TYPO-TRANSITIVE-001']);
    expect(findings[0]).toMatchObject({ severity: 'info', file: 'package-lock.json' });
    expect(findings[0]?.message).toMatch(/separator/);
  });

  it('keeps a direct separator on its own id and a direct one-edit name off this lane', async () => {
    setFlag('NPM_TYPO_TRANSITIVE');
    setFlag('NPM_SEPARATOR');
    const direct = await laneFindings(depth({ name: 'app', dependencies: { 'socket_io.client': '1.0.0' } }));
    expect(ids(direct)).toEqual(['DEPS-SEPARATOR-001']);
    setAll();
    const typosquat = await laneFindings(depth(
      { name: 'app', dependencies: { expresss: '1.0.0' } },
      lockWith(['expresss']),
    ));
    expect(typosquat).toEqual([]);
    expect(findTyposquats(
      [{ name: 'expresss', version: '1.0.0', path: 'node_modules/expresss' }],
      { directNames: new Set(['expresss']) },
    )).toEqual([expect.objectContaining({ name: 'expresss', distance: 1 })]);
  });

  it('names every matching transitive check on one row', async () => {
    setFlag('NPM_TYPO_TRANSITIVE');
    setFlag('NPM_BIDI');
    setFlag('NPM_MIXEDSCRIPT');
    const name = 'expres\u0441\u202E';
    const findings = await laneFindings(depth(
      { name: 'app', dependencies: { express: '1.0.0' } },
      {
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/express': { version: '1.0.0' },
          [`node_modules/express/node_modules/${name}`]: { version: '1.0.0' },
        },
      },
    ));
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('DEPS-TYPO-TRANSITIVE-001');
    expect(findings[0]?.message).toMatch(/bidi/);
    expect(findings[0]?.message).toMatch(/mixed script/);
  });

  it('flags an empty name and a name longer than 214 characters', async () => {
    setFlag('NPM_NAME_LENGTH');
    const long = 'a'.repeat(215);
    const findings = await laneFindings(depth({ name: 'app', dependencies: { '': '1.0.0', [long]: '1.0.0' } }));
    expect(ids(findings)).toEqual(['DEPS-NAME-LENGTH-001', 'DEPS-NAME-LENGTH-001']);
    expect(findings.every((finding) => finding.severity === 'high')).toBe(true);
  });

  it('does not flag a normal name or a name of exactly 214 characters', async () => {
    setFlag('NPM_NAME_LENGTH');
    const exact = 'b'.repeat(214);
    const findings = await laneFindings(depth({ name: 'app', dependencies: { express: '1.0.0', [exact]: '1.0.0' } }));
    expect(findings).toEqual([]);
  });

  it('flags two locked names that differ only by ASCII case', async () => {
    setFlag('NPM_NAME_CASE');
    const findings = await laneFindings(depth(
      { name: 'app' },
      {
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/express': { version: '4.0.0' },
          'node_modules/Express': { version: '1.0.0' },
        },
      },
    ));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'DEPS-NAME-CASE-001', severity: 'high' });
    expect(findings[0]?.message).toMatch(/Express/);
    expect(findings[0]?.message).toMatch(/express/);
  });

  it('does not flag distinct locked names', async () => {
    setFlag('NPM_NAME_CASE');
    const findings = await laneFindings(depth({ name: 'app' }, lockWith(['express', 'lodash'])));
    expect(findings).toEqual([]);
  });

  it('flags a percent sign in a dependency name', async () => {
    setFlag('NPM_NAME_ENCODED');
    const hit = await laneFindings(depth({ name: 'app', dependencies: { 'foo%2fbar': '1.0.0' } }));
    const ok = await laneFindings(depth({ name: 'app', dependencies: { express: '1.0.0' } }));
    expect(ids(hit)).toEqual(['DEPS-NAME-ENCODED-001']);
    expect(hit[0]).toMatchObject({ severity: 'high' });
    expect(ok).toEqual([]);
  });

  it('flags an alias whose requested name is popular and whose target is different', async () => {
    setFlag('NPM_ALIAS_SQUAT');
    setFlag('NPM_ALIAS');
    const input = depth({ name: 'app', dependencies: { express: 'npm:not-express@1.2.3' } });
    const ours = await laneFindings(input);
    const theirs = await laneAFindings(input);
    const combined = [...ours, ...theirs].map((finding) => finding.ruleId);
    expect(combined).toContain('DEPS-ALIAS-SQUAT-001');
    expect(ours.map((finding) => finding.ruleId)).not.toContain('DEPS-NPMALIAS-001');
    expect(ours[0]).toMatchObject({ severity: 'high' });
    expect(ours[0]?.message).toMatch(/express/);
    expect(ours[0]?.message).toMatch(/not-express/);
    if (theirs.some((finding) => finding.ruleId === 'DEPS-NPMALIAS-001')) {
      expect(combined).toEqual(expect.arrayContaining(['DEPS-NPMALIAS-001', 'DEPS-ALIAS-SQUAT-001']));
    }
  });

  it('does not flag an alias whose target is that same popular package, or a request that is not popular', async () => {
    setFlag('NPM_ALIAS_SQUAT');
    const same = await laneFindings(depth({ name: 'app', dependencies: { express: 'npm:express@4.18.2' } }));
    const other = await laneFindings(depth({ name: 'app', dependencies: { 'not-a-popular-alias': 'npm:other@1.0.0' } }));
    expect(same).toEqual([]);
    expect(other).toEqual([]);
  });

  it('flags a dependency whose name is the project name when the spec is not a workspace path', async () => {
    setFlag('NPM_SELFNAME');
    const findings = await laneFindings(depth({ name: 'my-app', dependencies: { 'my-app': '^1.0.0' } }));
    expect(ids(findings)).toEqual(['DEPS-SELFNAME-001']);
    expect(findings[0]).toMatchObject({ severity: 'medium' });
  });

  it('does not flag a workspace spec of the same name or a different name', async () => {
    setFlag('NPM_SELFNAME');
    const workspace = await laneFindings(depth({ name: 'my-app', dependencies: { 'my-app': 'workspace:*' } }));
    const file = await laneFindings(depth({ name: 'my-app', dependencies: { 'my-app': 'file:./packages/my-app' } }));
    const other = await laneFindings(depth({ name: 'my-app', dependencies: { express: '1.0.0' } }));
    expect(workspace).toEqual([]);
    expect(file).toEqual([]);
    expect(other).toEqual([]);
  });

  it('flags a workspace package resolved from registry.npmjs.org', async () => {
    setFlag('NPM_WORKSPACE_NAME');
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-lane-f-ws-'));
    dirs.push(cwd);
    await mkdir(join(cwd, 'packages', 'widget'), { recursive: true });
    await writeFile(join(cwd, 'packages', 'widget', 'package.json'), JSON.stringify({ name: 'widget', version: '1.0.0' }));
    const findings = await laneFindings(depth(
      { name: 'root', workspaces: ['packages/*'], dependencies: { widget: '*' } },
      {
        name: 'root',
        lockfileVersion: 3,
        packages: {
          '': { name: 'root' },
          'node_modules/widget': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/widget/-/widget-1.0.0.tgz',
          },
        },
      },
      { cwd },
    ));
    expect(ids(findings)).toEqual(['DEPS-WORKSPACE-NAME-001']);
    expect(findings[0]).toMatchObject({ severity: 'high' });
  });

  it('does not flag a link: resolution of a workspace package', async () => {
    setFlag('NPM_WORKSPACE_NAME');
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-lane-f-link-'));
    dirs.push(cwd);
    await mkdir(join(cwd, 'packages', 'widget'), { recursive: true });
    await writeFile(join(cwd, 'packages', 'widget', 'package.json'), JSON.stringify({ name: 'widget', version: '1.0.0' }));
    const findings = await laneFindings(depth(
      { name: 'root', workspaces: ['packages/*'] },
      {
        name: 'root',
        lockfileVersion: 3,
        packages: {
          '': { name: 'root' },
          'node_modules/widget': { version: '1.0.0', resolved: 'link:packages/widget' },
        },
      },
      { cwd },
    ));
    expect(findings).toEqual([]);
  });

  it('moves the existing popular names into models/npm-popular.json without a new rule id', () => {
    setFlag('NPM_POPULAR_LIST');
    const raw = JSON.parse(readFileSync(join(process.cwd(), 'models', 'npm-popular.json'), 'utf8')) as unknown;
    expect(Array.isArray(raw)).toBe(true);
    const names = (raw as { name: string }[]).map((entry) => entry.name);
    expect(new Set(names).size).toBe(names.length);
    expect(names).toEqual([...POPULAR_PACKAGES]);
    expect(createHash('sha256').update(names.join('\n')).digest('hex')).toBe(POPULAR_HASH);
    for (const name of names) {
      expect(name).toBe(name.toLowerCase());
      if (!LEGACY_UNGRAMMATICAL.has(name)) {
        expect(name).toMatch(PACKAGE_NAME);
        expect(name.length).toBeGreaterThan(0);
        expect(name.length).toBeLessThanOrEqual(214);
      }
    }
    expect(names.filter((name) => LEGACY_UNGRAMMATICAL.has(name)).sort()).toEqual(['node:test', 'uvu/assert']);
    expect(laneRows.map((row) => row.ruleId).join(' ')).not.toMatch(/POPULAR|DISTANCE/);
  });

  it('emits no name finding for a distance-2 name under the distance flag or the direct edit check', async () => {
    setAll();
    let min = 99;
    for (const popular of POPULAR_PACKAGES) {min = Math.min(min, levenshtein('exprexx', popular));}
    expect(min).toBe(2);
    const findings = await laneFindings(depth(
      { name: 'app', dependencies: { exprexx: '1.0.0' } },
      lockWith(['exprexx']),
    ));
    expect(findings.filter((finding) => finding.ruleId.startsWith('DEPS-'))).toEqual([]);
    expect(findTyposquats(
      [{ name: 'exprexx', version: '1.0.0', path: 'node_modules/exprexx' }],
      { directNames: new Set(['exprexx']) },
    )).toEqual([]);
  });

  it('does not flag clean-app when every lane F flag is on', async () => {
    setAll();
    const cwd = join(process.cwd(), 'test', 'fixtures', 'clean-app');
    const cacheDir = await tempCache();
    const findings = await laneFindings({
      cwd,
      files: ['package.json', 'package-lock.json'],
      manifestRaw: readFileSync(join(cwd, 'package.json'), 'utf8'),
      lockTexts: { 'package-lock.json': readFileSync(join(cwd, 'package-lock.json'), 'utf8') },
      cacheDir,
      offline: true,
    });
    expect(findings).toEqual([]);
  });
});
