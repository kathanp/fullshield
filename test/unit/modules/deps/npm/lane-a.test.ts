import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../../src/core/engine.js';
import type { Finding } from '../../../../../src/core/finding.js';

const GOOD = `sha512-${createHash('sha512').update('lane-a').digest('base64')}`;
const SHA1 = `sha1-${createHash('sha1').update('lane-a').digest('base64')}`;
const SHA256 = `sha256-${createHash('sha256').update('lane-a').digest('base64')}`;

const IDS = [
  'DEPS-SHRINKWRAP-001',
  'DEPS-SHRINKWRAP-002',
  'DEPS-LOCKVER-001',
  'DEPS-MULTLOCK-001',
  'DEPS-ROOTVER-001',
  'DEPS-NONSEMVER-001',
  'DEPS-NORESOLVED-001',
  'DEPS-RESOLVED-HOST-001',
  'DEPS-RESOLVED-HTTP-001',
  'DEPS-NOINTEGRITY-001',
  'DEPS-WEAKINTEGRITY-001',
  'DEPS-BADINTEGRITY-001',
  'DEPS-LINKDEP-001',
  'DEPS-GITDEP-001',
  'DEPS-NPMALIAS-001',
  'DEPS-BUNDLED-001',
  'DEPS-PEER-UNDECLARED-001',
  'DEPS-OPTIONAL-IMPORT-001',
  'DEPS-LOCKPATH-001',
  'DEPS-LOCKOMIT-001',
  'DEPS-DEV-PROD-EDGE-001',
] as const;

const FLAGS = [
  'FULLSHIELD_EXPERIMENTAL_NPM_SHRINKWRAP',
  'FULLSHIELD_EXPERIMENTAL_NPM_LOCKVER',
  'FULLSHIELD_EXPERIMENTAL_NPM_MULTLOCK',
  'FULLSHIELD_EXPERIMENTAL_NPM_ROOTVER',
  'FULLSHIELD_EXPERIMENTAL_NPM_NONSEMVER',
  'FULLSHIELD_EXPERIMENTAL_NPM_NORESOLVED',
  'FULLSHIELD_EXPERIMENTAL_NPM_RESOLVED_HOST',
  'FULLSHIELD_EXPERIMENTAL_NPM_RESOLVED_HTTP',
  'FULLSHIELD_EXPERIMENTAL_NPM_NOINTEGRITY',
  'FULLSHIELD_EXPERIMENTAL_NPM_WEAKINTEGRITY',
  'FULLSHIELD_EXPERIMENTAL_NPM_BADINTEGRITY',
  'FULLSHIELD_EXPERIMENTAL_NPM_LINKDEP',
  'FULLSHIELD_EXPERIMENTAL_NPM_GITDEP',
  'FULLSHIELD_EXPERIMENTAL_NPM_ALIAS',
  'FULLSHIELD_EXPERIMENTAL_NPM_BUNDLED',
  'FULLSHIELD_EXPERIMENTAL_NPM_PEER',
  'FULLSHIELD_EXPERIMENTAL_NPM_OPTIONAL',
  'FULLSHIELD_EXPERIMENTAL_NPM_LOCKPATH',
  'FULLSHIELD_EXPERIMENTAL_NPM_LOCKOMIT',
  'FULLSHIELD_EXPERIMENTAL_NPM_DEVPROD',
] as const;

const cleanApp = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const dirs: string[] = [];

function manifest(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ name: 'lane-a-app', version: '1.0.0', private: true, ...extra }, null, 2);
}

function reg(name: string, extra: Record<string, unknown> = {}, version = '1.2.3'): Record<string, unknown> {
  return {
    version,
    resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    integrity: GOOD,
    ...extra,
  };
}

function lock(packages: Record<string, unknown>, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    name: 'lane-a-app',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages,
    ...extra,
  }, null, 2);
}

function of(findings: Finding[], id: string): Finding[] {
  return findings.filter((finding) => finding.ruleId === id);
}

async function project(files: Record<string, string>): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-lane-a-'));
  dirs.push(cwd);
  for (const [rel, text] of Object.entries(files)) {
    const full = join(cwd, rel);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, text);
  }
  return cwd;
}

async function run(files: Record<string, string>, ...flags: string[]): Promise<Finding[]> {
  for (const flag of flags) {process.env[flag] = '1';}
  const cwd = await project(files);
  const result = await scan({ cwd, modules: ['deps'], offline: true });
  return result.findings;
}

afterEach(async () => {
  for (const flag of FLAGS) {delete process.env[flag];}
  for (const dir of dirs.splice(0)) {await rm(dir, { recursive: true, force: true });}
});

describe('npm lane A phases 108–127', () => {
  it('emits none of the lane ids when the flags are off', async () => {
    const findings = await run({
      'package.json': manifest({ dependencies: { 'lane-a-hostpkg': '1.2.3' } }),
      'package-lock.json': lock({
        '': { version: '9.9.9', dependencies: {} },
        'node_modules/lane-a-hostpkg': {
          version: 'abc123',
          resolved: 'http://evil.example/lane-a-hostpkg.tgz',
        },
      }),
      'yarn.lock': '# yarn lockfile v1\n',
    });
    expect(findings.filter((finding) => (IDS as readonly string[]).includes(finding.ruleId))).toEqual([]);
  });

  it('emits none of the lane ids on clean-app with every lane flag set', async () => {
    for (const flag of FLAGS) {process.env[flag] = '1';}
    const result = await scan({ cwd: cleanApp, modules: ['deps'], offline: true });
    expect(result.findings.filter((finding) => (IDS as readonly string[]).includes(finding.ruleId))).toEqual([]);
  });

  it('reports shrinkwrap when it is the only lockfile', async () => {
    const body = lock({
      '': { version: '1.0.0' },
      'node_modules/lane-a-shrinkpkg': reg('lane-a-shrinkpkg'),
    });
    const findings = await run({
      'package.json': manifest(),
      'npm-shrinkwrap.json': body,
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_SHRINKWRAP');
    expect(of(findings, 'DEPS-SHRINKWRAP-001')).toMatchObject([
      { severity: 'info', file: 'npm-shrinkwrap.json' },
    ]);
    expect(of(findings, 'DEPS-SHRINKWRAP-002')).toEqual([]);
  });

  it('does not report shrinkwrap for package-lock alone or for matching sets', async () => {
    const body = lock({
      '': { version: '1.0.0' },
      'node_modules/lane-a-shrinkpkg': reg('lane-a-shrinkpkg'),
    });
    const onlyLock = await run({
      'package.json': manifest(),
      'package-lock.json': body,
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_SHRINKWRAP');
    const same = await run({
      'package.json': manifest(),
      'package-lock.json': body,
      'npm-shrinkwrap.json': body,
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_SHRINKWRAP');
    expect(of(onlyLock, 'DEPS-SHRINKWRAP-001')).toEqual([]);
    expect(of(onlyLock, 'DEPS-SHRINKWRAP-002')).toEqual([]);
    expect(of(same, 'DEPS-SHRINKWRAP-001')).toEqual([]);
    expect(of(same, 'DEPS-SHRINKWRAP-002')).toEqual([]);
  });

  it('reports shrinkwrap and package-lock sets that differ', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-shrinkpkg': reg('lane-a-shrinkpkg', {}, '1.2.3'),
      }),
      'npm-shrinkwrap.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-shrinkpkg': reg('lane-a-shrinkpkg', {}, '1.2.4'),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_SHRINKWRAP');
    expect(of(findings, 'DEPS-SHRINKWRAP-002')).toMatchObject([{ severity: 'high' }]);
    expect(of(findings, 'DEPS-SHRINKWRAP-002')[0]?.message).toMatch(/name@version/);
    expect(of(findings, 'DEPS-SHRINKWRAP-001')).toEqual([]);
  });

  it('reports lockfileVersion missing, 1, or greater than 3', async () => {
    const flag = 'FULLSHIELD_EXPERIMENTAL_NPM_LOCKVER';
    const missing = await run({
      'package.json': manifest(),
      'package-lock.json': JSON.stringify({ packages: { '': { version: '1.0.0' } } }),
    }, flag);
    const v1 = await run({
      'package.json': manifest(),
      'package-lock.json': JSON.stringify({
        lockfileVersion: 1,
        dependencies: { 'lane-a-v1pkg': { version: '1.2.3' } },
      }),
    }, flag);
    const v4 = await run({
      'package.json': manifest(),
      'package-lock.json': lock({ '': { version: '1.0.0' } }, { lockfileVersion: 4 }),
    }, flag);
    expect(of(missing, 'DEPS-LOCKVER-001').map((finding) => finding.severity)).toEqual(['medium']);
    expect(of(missing, 'DEPS-LOCKVER-001')[0]?.message).toMatch(/missing/);
    expect(of(v1, 'DEPS-LOCKVER-001')[0]?.message).toMatch(/lockfileVersion is 1/);
    expect(of(v4, 'DEPS-LOCKVER-001')[0]?.message).toMatch(/lockfileVersion is 4/);
  });

  it('accepts lockfileVersion 2 and 3', async () => {
    const flag = 'FULLSHIELD_EXPERIMENTAL_NPM_LOCKVER';
    const v2 = await run({
      'package.json': manifest(),
      'package-lock.json': lock({ '': { version: '1.0.0' } }, { lockfileVersion: 2 }),
    }, flag);
    const v3 = await run({
      'package.json': manifest(),
      'package-lock.json': lock({ '': { version: '1.0.0' } }),
    }, flag);
    expect(of(v2, 'DEPS-LOCKVER-001')).toEqual([]);
    expect(of(v3, 'DEPS-LOCKVER-001')).toEqual([]);
  });

  it('names every lockfile when two or more exist', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({ '': { version: '1.0.0' } }),
      'yarn.lock': '# yarn lockfile v1\n',
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_MULTLOCK');
    const hit = of(findings, 'DEPS-MULTLOCK-001');
    expect(hit).toMatchObject([{ severity: 'medium' }]);
    expect(hit[0]?.message).toMatch(/package-lock\.json/);
    expect(hit[0]?.message).toMatch(/yarn\.lock/);
  });

  it('does not report a single lockfile', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({ '': { version: '1.0.0' } }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_MULTLOCK');
    expect(of(findings, 'DEPS-MULTLOCK-001')).toEqual([]);
  });

  it('reports a root version that differs from package.json', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({ '': { version: '2.0.0' } }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_ROOTVER');
    const hit = of(findings, 'DEPS-ROOTVER-001');
    expect(hit).toMatchObject([{ severity: 'medium' }]);
    expect(hit[0]?.message).toMatch(/2\.0\.0/);
    expect(hit[0]?.message).toMatch(/1\.0\.0/);
  });

  it('accepts equal root versions, a missing root entry, and a workspace package', async () => {
    const flag = 'FULLSHIELD_EXPERIMENTAL_NPM_ROOTVER';
    const equal = await run({
      'package.json': manifest(),
      'package-lock.json': lock({ '': { version: '1.0.0' } }),
    }, flag);
    const noRoot = await run({
      'package.json': manifest({ version: '9.9.9' }),
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        dependencies: { 'lane-a-noroot': { version: '1.2.3' } },
      }),
    }, flag);
    const workspace = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'packages/lane-a-workspace': { version: '9.9.9' },
      }),
    }, flag);
    expect(of(equal, 'DEPS-ROOTVER-001')).toEqual([]);
    expect(of(noRoot, 'DEPS-ROOTVER-001')).toEqual([]);
    expect(of(workspace, 'DEPS-ROOTVER-001')).toEqual([]);
  });

  it('reports locked versions that are not MAJOR.MINOR.PATCH', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-sha': reg('lane-a-sha', {}, 'abc123def'),
        'node_modules/lane-a-star': { version: '*' },
        'node_modules/lane-a-empty': { version: '' },
        'node_modules/lane-a-filever': { version: 'file:./lane-a-filever' },
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_NONSEMVER');
    const hits = of(findings, 'DEPS-NONSEMVER-001');
    expect(hits.every((finding) => finding.severity === 'medium')).toBe(true);
    const text = hits.map((finding) => finding.message).join('\n');
    expect(text).toMatch(/abc123def/);
    expect(text).toMatch(/\*/);
    expect(text).toMatch(/empty version/);
    expect(text).toMatch(/file:\.\/lane-a-filever/);
  });

  it('accepts 1.2.3 and 1.2.3-beta.1', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-stable': reg('lane-a-stable', {}, '1.2.3'),
        'node_modules/lane-a-pre': reg('lane-a-pre', {}, '1.2.3-beta.1'),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_NONSEMVER');
    expect(of(findings, 'DEPS-NONSEMVER-001')).toEqual([]);
  });

  it('reports a semver packages entry with no resolved URL', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-bare': { version: '1.2.3' },
        'node_modules/lane-a-withdeps': { version: '1.2.4', dependencies: { 'lane-a-bare': '1.2.3' } },
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_NORESOLVED');
    const hits = of(findings, 'DEPS-NORESOLVED-001');
    expect(hits).toHaveLength(2);
    expect(hits.every((finding) => finding.severity === 'medium')).toBe(true);
    expect(hits.map((finding) => finding.snippet).sort()).toEqual([
      'lane-a-bare@1.2.3',
      'lane-a-withdeps@1.2.4',
    ]);
  });

  it('accepts a resolved URL, a link row, and a version-license row', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-ok': reg('lane-a-ok'),
        'node_modules/lane-a-link': { version: '1.2.3', link: true },
        'node_modules/lane-a-license': { version: '1.2.3', license: 'MIT' },
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_NORESOLVED');
    expect(of(findings, 'DEPS-NORESOLVED-001')).toEqual([]);
  });

  it('reports an https resolved host other than registry.npmjs.org', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-evil': {
          version: '1.2.3',
          resolved: 'https://evil.example/lane-a-evil.tgz',
          integrity: GOOD,
        },
        'node_modules/lane-a-ok': reg('lane-a-ok'),
        'node_modules/lane-a-clear': {
          version: '1.2.3',
          resolved: 'http://evil.example/lane-a-clear.tgz',
          integrity: GOOD,
        },
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_RESOLVED_HOST');
    const hits = of(findings, 'DEPS-RESOLVED-HOST-001');
    expect(hits).toMatchObject([{ severity: 'high' }]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toMatch(/evil\.example/);
    expect(hits[0]?.message).not.toMatch(/lane-a-ok/);
  });

  it('accepts registry.npmjs.org', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-ok': reg('lane-a-ok'),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_RESOLVED_HOST');
    expect(of(findings, 'DEPS-RESOLVED-HOST-001')).toEqual([]);
  });

  it('reports an http resolved URL and ignores git+ssh', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-clear': {
          version: '1.2.3',
          resolved: 'http://registry.npmjs.org/lane-a-clear/-/lane-a-clear-1.2.3.tgz',
          integrity: GOOD,
        },
        'node_modules/lane-a-git': {
          version: '1.2.3',
          resolved: 'git+ssh://git@github.com/example/lane-a.git',
        },
        'node_modules/lane-a-ok': reg('lane-a-ok'),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_RESOLVED_HTTP');
    const hits = of(findings, 'DEPS-RESOLVED-HTTP-001');
    expect(hits).toHaveLength(1);
    expect(hits[0]?.severity).toBe('high');
    expect(hits[0]?.message).toMatch(/http:\/\/registry\.npmjs\.org/);
    expect(hits[0]?.message).not.toMatch(/git\+ssh/);
  });

  it('does not report an https registry URL as cleartext', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-ok': reg('lane-a-ok'),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_RESOLVED_HTTP');
    expect(of(findings, 'DEPS-RESOLVED-HTTP-001')).toEqual([]);
  });

  it('reports a registry URL with missing or empty integrity', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-missing': {
          version: '1.2.3',
          resolved: 'https://registry.npmjs.org/lane-a-missing/-/lane-a-missing-1.2.3.tgz',
        },
        'node_modules/lane-a-blank': {
          version: '1.2.3',
          resolved: 'https://registry.npmjs.org/lane-a-blank/-/lane-a-blank-1.2.3.tgz',
          integrity: '',
        },
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_NOINTEGRITY');
    const hits = of(findings, 'DEPS-NOINTEGRITY-001');
    expect(hits).toHaveLength(2);
    expect(hits.every((finding) => finding.severity === 'high')).toBe(true);
  });

  it('accepts integrity and ignores link and file rows', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-ok': reg('lane-a-ok'),
        'node_modules/lane-a-link': { version: '1.2.3', resolved: 'link:./lane-a-link' },
        'node_modules/lane-a-file': { version: '1.2.3', resolved: 'file:./lane-a-file' },
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_NOINTEGRITY');
    expect(of(findings, 'DEPS-NOINTEGRITY-001')).toEqual([]);
  });

  it('reports sha1 and sha256 integrity', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-sha1': reg('lane-a-sha1', { integrity: SHA1 }),
        'node_modules/lane-a-sha256': reg('lane-a-sha256', { integrity: SHA256 }),
        'node_modules/lane-a-none': {
          version: '1.2.3',
          resolved: 'https://registry.npmjs.org/lane-a-none/-/lane-a-none-1.2.3.tgz',
        },
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_WEAKINTEGRITY');
    const hits = of(findings, 'DEPS-WEAKINTEGRITY-001');
    expect(hits).toHaveLength(2);
    expect(hits.every((finding) => finding.severity === 'medium')).toBe(true);
    expect(hits.map((finding) => finding.snippet).join('\n')).toMatch(/sha1-/);
    expect(hits.map((finding) => finding.snippet).join('\n')).toMatch(/sha256-/);
  });

  it('accepts sha512 and a missing integrity', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-ok': reg('lane-a-ok'),
        'node_modules/lane-a-none': {
          version: '1.2.3',
          resolved: 'https://registry.npmjs.org/lane-a-none/-/lane-a-none-1.2.3.tgz',
        },
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_WEAKINTEGRITY');
    expect(of(findings, 'DEPS-WEAKINTEGRITY-001')).toEqual([]);
  });

  it('reports integrity that is not algo-base64', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-bad': reg('lane-a-bad', { integrity: 'sha512-***' }),
        'node_modules/lane-a-words': reg('lane-a-words', { integrity: 'not-an-integrity' }),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_BADINTEGRITY');
    const hits = of(findings, 'DEPS-BADINTEGRITY-001');
    expect(hits).toHaveLength(2);
    expect(hits.every((finding) => finding.severity === 'high')).toBe(true);
  });

  it('accepts a well-formed sha512 and a well-formed sha1', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-ok': reg('lane-a-ok'),
        'node_modules/lane-a-sha1': reg('lane-a-sha1', { integrity: SHA1 }),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_BADINTEGRITY');
    expect(of(findings, 'DEPS-BADINTEGRITY-001')).toEqual([]);
  });

  it('reports file and link dependencies, and raises severity when .. escapes', async () => {
    const findings = await run({
      'package.json': manifest({
        dependencies: {
          'lane-a-inside': 'file:./vendor/lane-a-inside',
          'lane-a-outside': 'file:../lane-a-outside',
        },
      }),
      'package-lock.json': lock({ '': { version: '1.0.0' } }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_LINKDEP');
    const hits = of(findings, 'DEPS-LINKDEP-001');
    const inside = hits.find((finding) => finding.snippet === 'file:./vendor/lane-a-inside');
    const outside = hits.find((finding) => finding.snippet === 'file:../lane-a-outside');
    expect(inside?.severity).toBe('medium');
    expect(inside?.message).toMatch(/file:\.\/vendor\/lane-a-inside/);
    expect(outside?.severity).toBe('high');
    expect(outside?.message).toMatch(/file:\.\.\/lane-a-outside/);
    expect(outside?.message).toMatch(/escapes the repo root/);
  });

  it('does not report a registry tarball as a file dependency', async () => {
    const findings = await run({
      'package.json': manifest({ dependencies: { 'lane-a-ok': '1.2.3' } }),
      'package-lock.json': lock({
        '': { version: '1.0.0', dependencies: { 'lane-a-ok': '1.2.3' } },
        'node_modules/lane-a-ok': reg('lane-a-ok'),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_LINKDEP');
    expect(of(findings, 'DEPS-LINKDEP-001')).toEqual([]);
  });

  it('reports git, github, gitlab, bitbucket, and gist specs', async () => {
    const findings = await run({
      'package.json': manifest({
        dependencies: {
          'lane-a-git': 'git+ssh://git@github.com/example/lane-a.git',
          'lane-a-hub': 'github:example/lane-a',
        },
      }),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-lab': { version: '1.2.3', resolved: 'gitlab:example/lane-a' },
        'node_modules/lane-a-bucket': { version: '1.2.3', resolved: 'bitbucket:example/lane-a' },
        'node_modules/lane-a-gist': { version: '1.2.3', resolved: 'gist:abcdef' },
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_GITDEP');
    const hits = of(findings, 'DEPS-GITDEP-001');
    expect(hits.length).toBeGreaterThanOrEqual(5);
    expect(hits.every((finding) => finding.severity === 'high')).toBe(true);
    const text = hits.map((finding) => finding.message).join('\n');
    expect(text).toMatch(/git\+ssh:/);
    expect(text).toMatch(/github:/);
    expect(text).toMatch(/gitlab:/);
    expect(text).toMatch(/bitbucket:/);
    expect(text).toMatch(/gist:/);
  });

  it('does not report a registry tarball as a git dependency', async () => {
    const findings = await run({
      'package.json': manifest({ dependencies: { 'lane-a-ok': '1.2.3' } }),
      'package-lock.json': lock({
        '': { version: '1.0.0', dependencies: { 'lane-a-ok': '1.2.3' } },
        'node_modules/lane-a-ok': reg('lane-a-ok'),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_GITDEP');
    expect(of(findings, 'DEPS-GITDEP-001')).toEqual([]);
  });

  it('reports an npm alias whose target name differs', async () => {
    const findings = await run({
      'package.json': manifest({ dependencies: { 'lane-a-wanted': 'npm:lane-a-target@9.9.9' } }),
      'package-lock.json': lock({ '': { version: '1.0.0' } }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_ALIAS');
    const hits = of(findings, 'DEPS-NPMALIAS-001');
    expect(hits).toMatchObject([{ severity: 'medium', snippet: 'lane-a-wanted' }]);
    expect(hits[0]?.message).toMatch(/lane-a-target@9\.9\.9/);
  });

  it('accepts an alias whose name matches and a normal entry', async () => {
    const findings = await run({
      'package.json': manifest({
        dependencies: {
          'lane-a-same': 'npm:lane-a-same@1.2.3',
          'lane-a-normal': '1.2.3',
        },
      }),
      'package-lock.json': lock({
        '': { version: '1.0.0', dependencies: { 'lane-a-normal': '1.2.3' } },
        'node_modules/lane-a-normal': reg('lane-a-normal'),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_ALIAS');
    expect(of(findings, 'DEPS-NPMALIAS-001')).toEqual([]);
  });

  it('reports a bundled entry the root bundle list does not name', async () => {
    const findings = await run({
      'package.json': manifest({ bundleDependencies: ['lane-a-other'] }),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-inbundle': reg('lane-a-inbundle', { inBundle: true }),
        'node_modules/lane-a-bundledflag': reg('lane-a-bundledflag', { bundled: true }),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_BUNDLED');
    const hits = of(findings, 'DEPS-BUNDLED-001');
    expect(hits.map((finding) => finding.snippet).sort()).toEqual([
      'lane-a-bundledflag',
      'lane-a-inbundle',
    ]);
    expect(hits.every((finding) => finding.severity === 'medium')).toBe(true);
  });

  it('accepts a bundled package named by the root array', async () => {
    const findings = await run({
      'package.json': manifest({ bundleDependencies: ['lane-a-inbundle'] }),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-inbundle': reg('lane-a-inbundle', { inBundle: true }),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_BUNDLED');
    expect(of(findings, 'DEPS-BUNDLED-001')).toEqual([]);
  });

  it('reports a production import of an undeclared peer', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-peerpkg': reg('lane-a-peerpkg', { peer: true }),
      }),
      'app.js': "const peer = require('lane-a-peerpkg');\npeer.use();\n",
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_PEER');
    const hits = of(findings, 'DEPS-PEER-UNDECLARED-001');
    expect(hits).toMatchObject([{ severity: 'medium', file: 'app.js', snippet: 'lane-a-peerpkg' }]);
  });

  it('accepts a declared peer and an import that exists only in a test file', async () => {
    const flag = 'FULLSHIELD_EXPERIMENTAL_NPM_PEER';
    const declared = await run({
      'package.json': manifest({ peerDependencies: { 'lane-a-peerpkg': '^1.2.3' } }),
      'package-lock.json': lock({
        '': { version: '1.0.0', peerDependencies: { 'lane-a-peerpkg': '^1.2.3' } },
        'node_modules/lane-a-peerpkg': reg('lane-a-peerpkg', { peer: true }),
      }),
      'app.js': "const peer = require('lane-a-peerpkg');\npeer.use();\n",
    }, flag);
    const testOnly = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-peerpkg': reg('lane-a-peerpkg', { peer: true }),
      }),
      'test/lane-a-peer.test.js': "const peer = require('lane-a-peerpkg');\npeer.use();\n",
    }, flag);
    expect(of(declared, 'DEPS-PEER-UNDECLARED-001')).toEqual([]);
    expect(of(testOnly, 'DEPS-PEER-UNDECLARED-001')).toEqual([]);
  });

  it('reports an optional import that is not inside try/catch', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-optpkg': reg('lane-a-optpkg', { optional: true }),
      }),
      'app.js': "const opt = require('lane-a-optpkg');\nopt.use();\n",
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_OPTIONAL');
    expect(of(findings, 'DEPS-OPTIONAL-IMPORT-001')).toMatchObject([
      { severity: 'low', file: 'app.js', snippet: 'lane-a-optpkg' },
    ]);
  });

  it('accepts an optional import inside try/catch and a required import', async () => {
    const findings = await run({
      'package.json': manifest({ dependencies: { 'lane-a-plainpkg': '1.2.3' } }),
      'package-lock.json': lock({
        '': { version: '1.0.0', dependencies: { 'lane-a-plainpkg': '1.2.3' } },
        'node_modules/lane-a-optpkg': reg('lane-a-optpkg', { optional: true }),
        'node_modules/lane-a-plainpkg': reg('lane-a-plainpkg'),
      }),
      'app.js': [
        'try {',
        "  const opt = require('lane-a-optpkg');",
        '  opt.use();',
        '} catch (err) {',
        '  err.message;',
        '}',
        "const plain = require('lane-a-plainpkg');",
        'plain.use();',
        '',
      ].join('\n'),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_OPTIONAL');
    expect(of(findings, 'DEPS-OPTIONAL-IMPORT-001')).toEqual([]);
  });

  it('reports packages keys outside node_modules and keys that contain ..', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'vendor/lane-a-pkg': { version: '1.2.3' },
        'node_modules/../lane-a-up': { version: '1.2.3' },
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_LOCKPATH');
    const hits = of(findings, 'DEPS-LOCKPATH-001');
    expect(hits.map((finding) => finding.snippet).sort()).toEqual([
      'node_modules/../lane-a-up',
      'vendor/lane-a-pkg',
    ]);
    expect(hits.every((finding) => finding.severity === 'high')).toBe(true);
  });

  it('accepts node_modules keys', async () => {
    const findings = await run({
      'package.json': manifest(),
      'package-lock.json': lock({
        '': { version: '1.0.0' },
        'node_modules/lane-a-ok': reg('lane-a-ok'),
        'node_modules/lane-a-ok/node_modules/lane-a-nested': reg('lane-a-nested'),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_LOCKPATH');
    expect(of(findings, 'DEPS-LOCKPATH-001')).toEqual([]);
  });

  it('reports a manifest dependency omitted from the lock root', async () => {
    const findings = await run({
      'package.json': manifest({
        dependencies: { 'lane-a-omitted': '^1.0.0', 'lane-a-kept': '^1.2.3' },
      }),
      'package-lock.json': lock({
        '': { version: '1.0.0', dependencies: { 'lane-a-kept': '^1.2.3' } },
        'node_modules/lane-a-kept': reg('lane-a-kept'),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_LOCKOMIT');
    const hits = of(findings, 'DEPS-LOCKOMIT-001');
    expect(hits).toMatchObject([{ severity: 'high', snippet: 'lane-a-omitted' }]);
    expect(hits).toHaveLength(1);
  });

  it('accepts a name present in the lock root', async () => {
    const findings = await run({
      'package.json': manifest({
        dependencies: { 'lane-a-kept': '^1.2.3', 'lane-a-top': '1.2.3' },
      }),
      'package-lock.json': lock({
        '': { version: '1.0.0', dependencies: { 'lane-a-kept': '^1.2.3' } },
        'node_modules/lane-a-kept': reg('lane-a-kept'),
      }, {
        dependencies: { 'lane-a-top': { version: '1.2.3' } },
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_LOCKOMIT');
    expect(of(findings, 'DEPS-LOCKOMIT-001')).toEqual([]);
  });

  it('reports a dev package required by a production package', async () => {
    const findings = await run({
      'package.json': manifest({ dependencies: { 'lane-a-prod': '1.2.3' } }),
      'package-lock.json': lock({
        '': { version: '1.0.0', dependencies: { 'lane-a-prod': '1.2.3' } },
        'node_modules/lane-a-prod': reg('lane-a-prod', { dependencies: { 'lane-a-devchild': '1.2.3' } }),
        'node_modules/lane-a-devchild': reg('lane-a-devchild', { dev: true }),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_DEVPROD');
    const hits = of(findings, 'DEPS-DEV-PROD-EDGE-001');
    expect(hits).toMatchObject([{ severity: 'medium' }]);
    expect(hits[0]?.message).toMatch(/lane-a-devchild/);
    expect(hits[0]?.message).toMatch(/lane-a-prod/);
  });

  it('accepts a dev-only edge and a production package with no dev dependency', async () => {
    const findings = await run({
      'package.json': manifest({
        dependencies: { 'lane-a-prod': '1.2.3' },
        devDependencies: { 'lane-a-eslint': '8.0.0' },
      }),
      'package-lock.json': lock({
        '': {
          version: '1.0.0',
          dependencies: { 'lane-a-prod': '1.2.3' },
          devDependencies: { 'lane-a-eslint': '8.0.0' },
        },
        'node_modules/lane-a-prod': reg('lane-a-prod'),
        'node_modules/lane-a-eslint': reg('lane-a-eslint', {
          dev: true,
          dependencies: { 'lane-a-minimatch': '3.0.0' },
        }, '8.0.0'),
        'node_modules/lane-a-minimatch': reg('lane-a-minimatch', { dev: true }, '3.0.0'),
      }),
    }, 'FULLSHIELD_EXPERIMENTAL_NPM_DEVPROD');
    expect(of(findings, 'DEPS-DEV-PROD-EDGE-001')).toEqual([]);
  });
});
