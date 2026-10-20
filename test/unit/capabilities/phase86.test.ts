import * as childProcess from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

const childCalls = vi.hoisted(() => [] as string[]);

vi.mock('node:child_process', async () => {
  const actual = await vi.importActual<typeof import('node:child_process')>('node:child_process');
  const { promisify } = await import('node:util');
  const wrap = (name: string, fn: (...args: never[]) => unknown) => {
    const wrapped = function (this: unknown, ...args: never[]) {
      childCalls.push(name);
      return Reflect.apply(fn, this, args);
    };
    Object.defineProperty(wrapped, 'length', { value: fn.length });
    const custom = (fn as unknown as { [promisify.custom]?: (...args: never[]) => unknown })[promisify.custom];
    if (custom !== undefined) {
      Object.defineProperty(wrapped, promisify.custom, {
        value(this: unknown, ...args: never[]) {
          childCalls.push(name);
          return Reflect.apply(custom, this, args);
        },
      });
    }
    return wrapped;
  };
  return {
    ...actual,
    spawn: wrap('spawn', actual.spawn as (...args: never[]) => unknown),
    spawnSync: wrap('spawnSync', actual.spawnSync as (...args: never[]) => unknown),
    exec: wrap('exec', actual.exec as (...args: never[]) => unknown),
    execSync: wrap('execSync', actual.execSync as (...args: never[]) => unknown),
    execFile: wrap('execFile', actual.execFile as (...args: never[]) => unknown),
    execFileSync: wrap('execFileSync', actual.execFileSync as (...args: never[]) => unknown),
    fork: wrap('fork', actual.fork as (...args: never[]) => unknown),
  };
});

import { createProgram } from '../../../src/cli/program.js';
import { scan } from '../../../src/core/engine.js';
import {
  formatCapabilityReport,
  introducedCapabilities,
  profileProject,
} from '../../../src/capabilities/index.js';

const root = process.cwd();
const appFixture = join(root, 'test/fixtures/capabilities-app');
const diffFixture = join(root, 'test/fixtures/capabilities-diff');
const dirs: string[] = [];

function stageApp(): string {
  const dir = reserve(join(tmpdir(), 'fullshield-cap-app-'));
  cpSync(appFixture, dir, { recursive: true });
  for (const name of ['direct-helper', 'inert-helper', 'quiet-helper']) {
    cpSync(join(dir, 'packages', name), join(dir, 'node_modules', name), { recursive: true });
  }
  return dir;
}

function stageDiff(): string {
  const dir = reserve(join(tmpdir(), 'fullshield-cap-diff-'));
  cpSync(diffFixture, dir, { recursive: true });
  cpSync(join(dir, 'packages/left'), join(dir, 'node_modules/left'), { recursive: true });
  cpSync(join(dir, 'packages/helper'), join(dir, 'node_modules/helper'), { recursive: true });
  const cache = join(dir, 'osv-cache', 'capabilities');
  mkdirSync(cache, { recursive: true });
  cpSync(join(dir, 'cache/sha512_oldleft.json'), join(cache, 'sha512_oldleft.json'));
  cpSync(join(dir, 'cache/sha512_oldhelper.json'), join(cache, 'sha512_oldhelper.json'));
  return dir;
}

function block(text: string, header: string): string {
  const lines = text.split('\n');
  const start = lines.findIndex((line) => line === header);
  if (start < 0) return '';
  const end = lines.findIndex((line, index) => index > start && line.length > 0 && !line.startsWith(' '));
  return lines.slice(start, end === -1 ? undefined : end).join('\n');
}

function reserve(prefix: string): string {
  const dir = mkdtempSync(prefix);
  dirs.push(dir);
  return dir;
}

async function runCli(args: string[]): Promise<{ out: string; err: string; code: number }> {
  const out: string[] = [];
  const err: string[] = [];
  const program = createProgram({
    out: (text) => out.push(text),
    err: (text) => err.push(text),
  });
  const before = process.exitCode;
  process.exitCode = undefined;
  await program.parseAsync(['node', 'fullshield', ...args]);
  const code = process.exitCode === undefined ? 0 : Number(process.exitCode);
  process.exitCode = before;
  return { out: out.join('\n'), err: err.join('\n'), code };
}

function spyCjsChildProcess(): { calls: () => number; restore: () => void } {
  const req = createRequire(import.meta.url);
  const cjs = req('node:child_process') as Record<string, (...args: never[]) => unknown>;
  const names = ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork'];
  const originals = new Map<string, (...args: never[]) => unknown>();
  let total = 0;
  for (const name of names) {
    const original = cjs[name];
    if (original === undefined) continue;
    originals.set(name, original);
    cjs[name] = ((...args: never[]) => {
      total += 1;
      return original(...args);
    }) as (...args: never[]) => unknown;
  }
  return {
    calls: () => total,
    restore: () => {
      for (const [name, original] of originals) cjs[name] = original;
    },
  };
}

describe('phase 86 capability profile', () => {
  afterEach(async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_CAPABILITIES;
    delete process.env.FULLSHIELD_EXPERIMENTAL_DEPS_DIFF;
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('attributes postinstall and child_process through the transitive package', () => {
    const dir = stageApp();
    const text = formatCapabilityReport(profileProject(dir, join(dir, 'osv-cache')));
    expect(text).toContain('direct-helper@1.0.0');
    expect(text).toContain('child_process via inert-helper@1.0.0');
    expect(text).toContain('install_script via inert-helper@1.0.0');
    const quiet = text.split('quiet-helper@1.0.0')[1] ?? '';
    expect(quiet).toContain('(none)');
    expect(quiet).not.toContain('child_process');
    expect(quiet).not.toContain('install_script');
  });

  it('emits SUPPLY-CAP-001 only for deny hits and never spawns a child process', async () => {
    const dir = stageApp();
    childCalls.length = 0;
    const cjs = spyCjsChildProcess();
    try {
      delete process.env.FULLSHIELD_EXPERIMENTAL_CAPABILITIES;
      const off = await scan({ cwd: dir, modules: ['deps'], offline: true });
      expect(off.findings.some((finding) => finding.ruleId === 'SUPPLY-CAP-001')).toBe(false);

      process.env.FULLSHIELD_EXPERIMENTAL_CAPABILITIES = '1';
      const on = await scan({ cwd: dir, modules: ['deps'], offline: true });
      const caps = on.findings.filter((finding) => finding.ruleId === 'SUPPLY-CAP-001');
      expect(caps.map((finding) => finding.message).sort()).toEqual([
        'direct-helper@1.0.0 capability child_process denied by deps.capabilityPolicy (via inert-helper@1.0.0)',
        'direct-helper@1.0.0 capability install_script denied by deps.capabilityPolicy (via inert-helper@1.0.0)',
      ]);
      expect(caps.every((finding) => finding.severity === 'high' && finding.module === 'deps')).toBe(true);
      expect(childCalls).toEqual([]);
      expect(cjs.calls()).toBe(0);
    } finally {
      cjs.restore();
    }
  });

  it('does not emit SUPPLY-CAP-001 for warn-only policy or a capability the package lacks', async () => {
    const dir = stageApp();
    const config = {
      modules: ['deps'],
      deps: {
        offline: true,
        cacheDir: 'osv-cache',
        capabilityPolicy: { warn: { child_process: ['*'], install_script: ['*'] }, deny: { net: ['*'] } },
      },
    };
    await writeFile(join(dir, 'fullshield.config.json'), JSON.stringify(config));
    process.env.FULLSHIELD_EXPERIMENTAL_CAPABILITIES = '1';
    const result = await scan({ cwd: dir, modules: ['deps'], offline: true });
    expect(result.findings.some((finding) => finding.ruleId === 'SUPPLY-CAP-001')).toBe(false);
  });

  it('reuses the integrity cache and does not treat a readFile package as a write', async () => {
    const dir = stageApp();
    const cache = join(dir, 'osv-cache');
    profileProject(dir, cache);
    await writeFile(join(dir, 'node_modules/inert-helper/index.js'), 'module.exports = 1;\n');
    const cached = formatCapabilityReport(profileProject(dir, cache));
    expect(cached).toContain('child_process via inert-helper@1.0.0');

    const lockPath = join(dir, 'package-lock.json');
    const lock = readFileSync(lockPath, 'utf8').replace('sha512-inerthelper', 'sha512-changed');
    await writeFile(lockPath, lock);
    const reread = formatCapabilityReport(profileProject(dir, cache));
    expect(reread).not.toContain('child_process');
    expect(reread).toContain('install_script via inert-helper@1.0.0');
    expect(reread.split('quiet-helper@1.0.0')[1]).toContain('(none)');
  });

  it('reports a version bump that adds net, child_process, and postinstall', () => {
    const dir = stageDiff();
    const before = readFileSync(join(diffFixture, 'old-lock.json'), 'utf8');
    const after = readFileSync(join(dir, 'package-lock.json'), 'utf8');
    const added = introducedCapabilities({
      beforeText: before,
      afterText: after,
      cwd: dir,
      cacheDir: join(dir, 'osv-cache'),
    });
    expect(added).toEqual(
      expect.arrayContaining([
        {
          name: 'left',
          from: '1.0.0',
          to: '1.0.1',
          capability: 'net',
          introducedBy: 'left@1.0.1',
        },
        {
          name: 'helper',
          from: '1.0.0',
          to: '1.0.1',
          capability: 'child_process',
          introducedBy: 'helper@1.0.1',
        },
        {
          name: 'helper',
          from: '1.0.0',
          to: '1.0.1',
          capability: 'install_script',
          introducedBy: 'helper@1.0.1',
        },
      ]),
    );
  });

  it('does not invent new capabilities when the old integrity is not cached', () => {
    const dir = stageDiff();
    const before = readFileSync(join(diffFixture, 'old-lock.json'), 'utf8');
    const after = readFileSync(join(dir, 'package-lock.json'), 'utf8');
    const added = introducedCapabilities({
      beforeText: before,
      afterText: after,
      cwd: dir,
      cacheDir: join(dir, 'empty-cache'),
    });
    expect(added).toEqual([]);
  });

  it('prints deps --capabilities and refuses without the flag', async () => {
    const dir = stageApp();
    const refused = await runCli(['deps', '--capabilities', dir]);
    expect(refused.code).toBe(2);
    expect(refused.err).toContain('FS-E014');
    expect(refused.err).toContain('FULLSHIELD_EXPERIMENTAL_CAPABILITIES');

    process.env.FULLSHIELD_EXPERIMENTAL_CAPABILITIES = '1';
    const printed = await runCli(['deps', '--capabilities', dir]);
    expect(printed.code).toBe(0);
    expect(printed.err).toBe('');
    expect(printed.out).toContain('child_process via inert-helper@1.0.0');
    expect(printed.out).toContain('install_script via inert-helper@1.0.0');
  });

  it('adds new capabilities on deps-diff only when the flag is set', async () => {
    const dir = stageDiff();
    const { execFileSync } = childProcess;
    execFileSync('git', ['init'], { cwd: dir });
    execFileSync('git', ['config', 'user.email', 'cap@test.local'], { cwd: dir });
    execFileSync('git', ['config', 'user.name', 'Cap Test'], { cwd: dir });
    await writeFile(join(dir, 'package-lock.json'), readFileSync(join(diffFixture, 'old-lock.json')));
    execFileSync('git', ['add', 'package-lock.json'], { cwd: dir });
    execFileSync('git', ['commit', '-m', 'old'], { cwd: dir });
    await writeFile(join(dir, 'package-lock.json'), readFileSync(join(diffFixture, 'package-lock.json')));

    process.env.FULLSHIELD_EXPERIMENTAL_DEPS_DIFF = '1';
    const plain = await runCli(['deps-diff', 'HEAD', dir, '--offline', '--json']);
    expect(plain.code).not.toBe(2);
    expect(plain.out).not.toContain('newCapabilities');

    process.env.FULLSHIELD_EXPERIMENTAL_CAPABILITIES = '1';
    const flagged = await runCli(['deps-diff', 'HEAD', dir, '--offline', '--json']);
    expect(flagged.code).not.toBe(2);
    expect(flagged.out).toContain('"capability": "net"');
    expect(flagged.out).toContain('"introducedBy": "left@1.0.1"');
    expect(flagged.out).toContain('"capability": "child_process"');
    expect(flagged.out).toContain('"capability": "install_script"');
  });

  it('keeps clean-app findings the same when the flag is on', async () => {
    const clean = join(root, 'test/fixtures/clean-app');
    delete process.env.FULLSHIELD_EXPERIMENTAL_CAPABILITIES;
    const off = await scan({ cwd: clean, offline: true });
    process.env.FULLSHIELD_EXPERIMENTAL_CAPABILITIES = '1';
    const on = await scan({ cwd: clean, offline: true });
    const key = (finding: { ruleId: string; file?: string; line?: number; severity: string }) =>
      `${finding.ruleId}|${finding.file ?? ''}|${finding.line ?? ''}|${finding.severity}`;
    expect(on.findings.map(key).sort()).toEqual(off.findings.map(key).sort());
    expect(on.findings.some((finding) => finding.ruleId === 'SUPPLY-CAP-001')).toBe(false);
  });

  it('detects each capability signal and stays quiet on the negative file', () => {
    const dir = reserve(join(tmpdir(), 'fullshield-cap-signals-'));
    const cases: Array<{ name: string; script?: string; file: string; extra?: string; caps: string[] }> = [
      { name: 'net-mod', file: "require('http');\nrequire('https');\nrequire('dgram');\n", caps: ['net'] },
      { name: 'fetch', file: 'fetch(url);\n', caps: ['net'] },
      { name: 'fs-write', file: "require('fs').writeFileSync('a', 'b');\n", caps: ['fs_write'] },
      { name: 'fs-read', file: "require('fs').readFileSync('a');\n", caps: [] },
      { name: 'env', file: 'const value = process.env.PATH;\n', caps: ['env'] },
      { name: 'no-env', file: 'const envName = 1;\n', caps: [] },
      { name: 'dynamic', file: 'require(modName);\n', caps: ['dynamic_require'] },
      { name: 'static-require', file: "require('path');\n", caps: [] },
      { name: 'code-exec', file: "const fn = new Function('return 1');\n", caps: ['eval'] },
      { name: 'vm', file: "const vm = require('vm');\nvm.runInNewContext('1');\n", caps: ['eval'] },
      { name: 'phase70', file: "eval(Buffer.from('YQ=='));\n", caps: ['eval', 'obfuscation'] },
      { name: 'hex', file: `const blob = '${'ab'.repeat(32)}';\n`, caps: ['obfuscation'] },
      { name: 'b64', file: `const blob = '${'Ab'.repeat(20)}+/${'Cd'.repeat(20)}';\n`, caps: ['obfuscation'] },
      { name: 'short-hex', file: "const blob = 'abcd';\n", caps: [] },
      { name: 'test-script', file: 'module.exports = 1;\n', script: 'node test.js', caps: [] },
    ];
    const packages: Record<string, { version: string; integrity: string }> = {};
    const deps: Record<string, string> = {};
    for (const row of cases) {
      const pkgDir = join(dir, 'node_modules', row.name);
      mkdirSync(pkgDir, { recursive: true });
      const manifest: { name: string; version: string; scripts?: { test: string } } = {
        name: row.name,
        version: '1.0.0',
      };
      if (row.script !== undefined) manifest.scripts = { test: row.script };
      writeFileSync(join(pkgDir, 'package.json'), JSON.stringify(manifest));
      writeFileSync(join(pkgDir, 'index.js'), row.file);
      if (row.extra !== undefined) writeFileSync(join(pkgDir, row.extra), '');
      packages[`node_modules/${row.name}`] = { version: '1.0.0', integrity: `sha512-${row.name}` };
      deps[row.name] = '1.0.0';
    }
    const nativeDir = join(dir, 'node_modules', 'native-addon');
    mkdirSync(nativeDir, { recursive: true });
    writeFileSync(join(nativeDir, 'package.json'), JSON.stringify({ name: 'native-addon', version: '1.0.0' }));
    writeFileSync(join(nativeDir, 'binding.gyp'), '{}\n');
    writeFileSync(join(nativeDir, 'addon.node'), '');
    packages['node_modules/native-addon'] = { version: '1.0.0', integrity: 'sha512-native' };
    deps['native-addon'] = '1.0.0';
    writeFileSync(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'signals', version: '1.0.0', dependencies: deps }),
    );
    writeFileSync(
      join(dir, 'package-lock.json'),
      JSON.stringify({
        name: 'signals',
        lockfileVersion: 3,
        packages: { '': { dependencies: deps }, ...Object.fromEntries(Object.entries(packages).map(([key, value]) => [key, value])) },
      }),
    );
    const text = formatCapabilityReport(profileProject(dir, join(dir, 'osv-cache')));
    for (const row of cases) {
      const section = block(text, `${row.name}@1.0.0`);
      if (row.caps.length === 0) expect(section).toContain('(none)');
      for (const cap of row.caps) expect(section).toContain(`${cap} via ${row.name}@1.0.0`);
      if (row.caps.length === 0) expect(section).not.toContain(' via ');
    }
    expect(text).toContain('native via native-addon@1.0.0');
    const escaped = `const packed = '${'\\x61'.repeat(8)}';\n`;
    const obDir = join(dir, 'node_modules', 'packed');
    mkdirSync(obDir, { recursive: true });
    writeFileSync(join(obDir, 'package.json'), JSON.stringify({ name: 'packed', version: '1.0.0' }));
    writeFileSync(join(obDir, 'index.js'), escaped);
    const lock = JSON.parse(readFileSync(join(dir, 'package-lock.json'), 'utf8')) as {
      packages: Record<string, { version?: string; integrity?: string; dependencies?: Record<string, string> }>;
    };
    const rootPkg = lock.packages[''];
    if (rootPkg?.dependencies !== undefined) rootPkg.dependencies.packed = '1.0.0';
    lock.packages['node_modules/packed'] = { version: '1.0.0', integrity: 'sha512-packed' };
    writeFileSync(join(dir, 'package-lock.json'), JSON.stringify(lock));
    const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { dependencies: Record<string, string> };
    manifest.dependencies.packed = '1.0.0';
    writeFileSync(join(dir, 'package.json'), JSON.stringify(manifest));
    const again = formatCapabilityReport(profileProject(dir, join(dir, 'fresh-cache')));
    expect(again).toContain('obfuscation via packed@1.0.0');
  });
});
