import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../../src/core/engine.js';
import { laneFindings, laneRows } from '../../../../../src/modules/deps/npm/lane-c.js';
import type { Finding } from '../../../../../src/core/finding.js';
import type { NpmDepthInput } from '../../../../../src/modules/deps/npm/types.js';

const OLD = '2020-01-01T00:00:00.000Z';
const TARBALL = 'https://registry.npmjs.org/widget/-/widget-1.0.0.tgz';
const RULE_IDS = [
  'DEPS-REG-INTEGRITY-001',
  'DEPS-REG-TARBALL-001',
  'DEPS-REG-DEPRECATED-001',
  'DEPS-REG-UNPUBLISHED-001',
  'DEPS-REG-NPMUSER-001',
  'DEPS-REG-MAINTAINER-001',
  'DEPS-REG-PROV-ABSENT-001',
  'DEPS-REG-BUILDER-001',
  'DEPS-REG-REPO-001',
  'DEPS-REG-SUBJECT-001',
  'DEPS-REG-TIME-001',
  'DEPS-REG-AGE-001',
  'DEPS-REG-INSTALLSCRIPT-001',
  'DEPS-REG-SIGNATURES-001',
  'DEPS-REG-ENGINES-001',
  'DEPS-REG-DRIFT-001',
  'DEPS-REG-DEPS-001',
  'DEPS-REG-PEER-001',
  'DEPS-REG-BIN-001',
  'DEPS-REG-REPOSITORY-001',
] as const;

const FLAGS = [
  'NPM_REG_INTEGRITY',
  'NPM_REG_TARBALL',
  'NPM_REG_DEPRECATED',
  'NPM_REG_UNPUBLISHED',
  'NPM_REG_NPMUSER',
  'NPM_REG_MAINTAINER',
  'NPM_REG_PROV_ABSENT',
  'NPM_REG_BUILDER',
  'NPM_REG_REPO',
  'NPM_REG_SUBJECT',
  'NPM_REG_TIME',
  'NPM_REG_TRANSITIVE_AGE',
  'NPM_REG_INSTALLSCRIPT',
  'NPM_REG_SIGNATURES',
  'NPM_REG_ENGINES',
  'NPM_REG_DRIFT',
  'NPM_REG_DEPS',
  'NPM_REG_PEER',
  'NPM_REG_BIN',
  'NPM_REG_REPOSITORY',
] as const;

const dirs: string[] = [];

function envFlag(name: string): string {
  return `FULLSHIELD_EXPERIMENTAL_${name}`;
}

function hoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 3_600_000).toISOString();
}

function versionDoc(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { dist: { integrity: 'sha512-same', tarball: TARBALL }, ...extra };
}

function doc(
  version: string,
  fields: Record<string, unknown> = {},
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return { time: { [version]: OLD }, versions: { [version]: versionDoc(fields) }, ...extra };
}

function locked(
  extra: Record<string, unknown> = {},
  root: Record<string, unknown> = { dependencies: { widget: '^1.0.0' } },
): Record<string, unknown> {
  return {
    '': root,
    'node_modules/widget': {
      version: '1.0.0',
      integrity: 'sha512-same',
      resolved: TARBALL,
      ...extra,
    },
  };
}

async function tempDir(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), 'fullshield-npm-c-'));
  dirs.push(cwd);
  await mkdir(join(cwd, 'registry'), { recursive: true });
  return cwd;
}

async function writeCache(cwd: string, name: string, packument: unknown, previous?: unknown): Promise<void> {
  const body: Record<string, unknown> = { fetchedAt: OLD, packument };
  if (previous !== undefined) {body.previous = previous;}
  await writeFile(join(cwd, 'registry', `${name.replaceAll('/', '__')}.json`), JSON.stringify(body));
}

interface RunOpts {
  flags: readonly string[];
  packages: Record<string, unknown>;
  caches?: Record<string, { packument: unknown; previous?: unknown }>;
  manifest?: string;
  config?: string;
  offline?: boolean;
}

async function run(opts: RunOpts): Promise<Finding[]> {
  for (const name of opts.flags) {process.env[envFlag(name)] = '1';}
  const cwd = await tempDir();
  if (opts.config !== undefined) {await writeFile(join(cwd, 'fullshield.config.json'), opts.config);}
  for (const [name, body] of Object.entries(opts.caches ?? {})) {
    await writeCache(cwd, name, body.packument, body.previous);
  }
  return laneFindings(inputOf(cwd, opts));
}

function inputOf(cwd: string, opts: RunOpts): NpmDepthInput {
  return {
    cwd,
    files: ['package.json', 'package-lock.json'],
    manifestRaw: opts.manifest ?? JSON.stringify({ dependencies: { widget: '^1.0.0' } }),
    lockTexts: {
      'package-lock.json': JSON.stringify({ name: 'app', lockfileVersion: 3, packages: opts.packages }),
    },
    cacheDir: cwd,
    offline: opts.offline ?? true,
  };
}

function ids(findings: Finding[]): string[] {
  return findings.map((finding) => finding.ruleId);
}

function expectOnly(findings: Finding[], id: string, severity: string): void {
  expect(ids(findings)).toEqual([id]);
  expect(findings[0]?.severity).toBe(severity);
}

afterEach(async () => {
  for (const dir of dirs.splice(0)) {await rm(dir, { recursive: true, force: true });}
});

describe('lane rows', () => {
  it('maps every phase 148-167 rule id', () => {
    expect(laneRows.map((row) => row.ruleId)).toEqual([...RULE_IDS]);
    expect(laneRows.every((row) => row.cwe.startsWith('CWE-'))).toBe(true);
  });
});

describe('phase 148 integrity', () => {
  it('flags a lock integrity that differs from the packument', async () => {
    const findings = await run({
      flags: ['NPM_REG_INTEGRITY'],
      packages: locked({ integrity: 'sha512-lock' }),
      caches: { widget: { packument: doc('1.0.0', { dist: { integrity: 'sha512-reg', tarball: TARBALL } }) } },
    });
    expectOnly(findings, 'DEPS-REG-INTEGRITY-001', 'critical');
  });

  it('does not flag a match or a missing side', async () => {
    const match = await run({
      flags: ['NPM_REG_INTEGRITY'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0') } },
    });
    const missing = await run({
      flags: ['NPM_REG_INTEGRITY'],
      packages: locked({ integrity: undefined }),
      caches: { widget: { packument: doc('1.0.0', { dist: { tarball: TARBALL } }) } },
    });
    const absent = await run({ flags: ['NPM_REG_INTEGRITY'], packages: locked() });
    expect(match).toEqual([]);
    expect(missing).toEqual([]);
    expect(absent).toEqual([]);
  });
});

describe('phase 149 tarball', () => {
  it('flags registry tarball URLs that differ without the query', async () => {
    const other = 'https://registry.npmjs.org/widget/-/widget-9.9.9.tgz';
    const findings = await run({
      flags: ['NPM_REG_TARBALL'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', { dist: { integrity: 'sha512-same', tarball: other } }) } },
    });
    expectOnly(findings, 'DEPS-REG-TARBALL-001', 'high');
  });

  it('does not flag equal URLs, query strings, or a non-registry lock URL', async () => {
    const queried = await run({
      flags: ['NPM_REG_TARBALL'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', { dist: { integrity: 'sha512-same', tarball: `${TARBALL}?x=1` } }) } },
    });
    const github = 'https://github.com/acme/widget/tarball.tgz';
    const foreign = await run({
      flags: ['NPM_REG_TARBALL'],
      packages: locked({ resolved: github }),
      caches: { widget: { packument: doc('1.0.0', { dist: { integrity: 'sha512-same', tarball: TARBALL } }) } },
    });
    expect(queried).toEqual([]);
    expect(foreign).toEqual([]);
  });
});

describe('phase 150 deprecated', () => {
  it('flags a packument deprecation the lock does not carry', async () => {
    const findings = await run({
      flags: ['NPM_REG_DEPRECATED'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', { deprecated: 'use something else' }) } },
    });
    expectOnly(findings, 'DEPS-REG-DEPRECATED-001', 'info');
  });

  it('does not flag a matching lock string or a version that is not deprecated', async () => {
    const same = await run({
      flags: ['NPM_REG_DEPRECATED'],
      packages: locked({ deprecated: 'use something else' }),
      caches: { widget: { packument: doc('1.0.0', { deprecated: 'use something else' }) } },
    });
    const live = await run({
      flags: ['NPM_REG_DEPRECATED'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0') } },
    });
    expect(same).toEqual([]);
    expect(live).toEqual([]);
  });
});

describe('phase 151 unpublished', () => {
  it('flags a version missing from the versions object', async () => {
    const findings = await run({
      flags: ['NPM_REG_UNPUBLISHED'],
      packages: locked(),
      caches: { widget: { packument: { versions: { '2.0.0': {} }, time: { '1.0.0': OLD } } } },
    });
    expectOnly(findings, 'DEPS-REG-UNPUBLISHED-001', 'critical');
  });

  it('does not treat a present version, a missing file, or a non-object versions as unpublished', async () => {
    const present = await run({
      flags: ['NPM_REG_UNPUBLISHED'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0') } },
    });
    const missing = await run({ flags: ['NPM_REG_UNPUBLISHED'], packages: locked() });
    const broken = await run({
      flags: ['NPM_REG_UNPUBLISHED'],
      packages: locked(),
      caches: { widget: { packument: { time: { '1.0.0': OLD } } } },
    });
    expect(present).toEqual([]);
    expect(missing).toEqual([]);
    expect(broken).toEqual([]);
  });
});

describe('phase 152 publisher', () => {
  it('flags a publisher who is not a maintainer', async () => {
    const findings = await run({
      flags: ['NPM_REG_NPMUSER'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', { _npmUser: { name: 'mallory' } }, { maintainers: [{ name: 'alice' }] }),
        },
      },
    });
    expectOnly(findings, 'DEPS-REG-NPMUSER-001', 'medium');
  });

  it('does not flag a listed publisher or a missing _npmUser', async () => {
    const listed = await run({
      flags: ['NPM_REG_NPMUSER'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', { _npmUser: { name: 'alice' } }, { maintainers: [{ name: 'alice' }] }),
        },
      },
    });
    const missing = await run({
      flags: ['NPM_REG_NPMUSER'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', {}, { maintainers: [{ name: 'alice' }] }) } },
    });
    expect(listed).toEqual([]);
    expect(missing).toEqual([]);
  });
});

describe('phase 153 maintainers', () => {
  it('flags a maintainer set that differs from the previous cache', async () => {
    const findings = await run({
      flags: ['NPM_REG_MAINTAINER'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', {}, { maintainers: [{ name: 'bob' }] }),
          previous: { maintainers: ['alice'] },
        },
      },
    });
    expectOnly(findings, 'DEPS-REG-MAINTAINER-001', 'medium');
  });

  it('does not flag the same set or the first sight of a package', async () => {
    const same = await run({
      flags: ['NPM_REG_MAINTAINER'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', {}, { maintainers: [{ name: 'bob' }, { name: 'alice' }] }),
          previous: { maintainers: ['alice', 'bob'] },
        },
      },
    });
    const first = await run({
      flags: ['NPM_REG_MAINTAINER'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', {}, { maintainers: [{ name: 'alice' }] }) } },
    });
    expect(same).toEqual([]);
    expect(first).toEqual([]);
  });
});

describe('phase 154 provenance absent', () => {
  it('flags a direct production version with no attestation or signature', async () => {
    const findings = await run({
      flags: ['NPM_REG_PROV_ABSENT'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0') } },
    });
    expectOnly(findings, 'DEPS-REG-PROV-ABSENT-001', 'info');
    expect(findings[0]?.message).toMatch(/not a claim that the package is malicious/);
  });

  it('does not flag attestations, signatures, transitive packages, or a cache miss', async () => {
    const attested = await run({
      flags: ['NPM_REG_PROV_ABSENT'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', { dist: { attestations: { url: 'https://registry.npmjs.org/a' }, integrity: 'sha512-same', tarball: TARBALL } }) } },
    });
    const signed = await run({
      flags: ['NPM_REG_PROV_ABSENT'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', { dist: { signatures: [{ keyid: 'k', sig: 's' }], integrity: 'sha512-same', tarball: TARBALL } }) } },
    });
    const dev = await run({
      flags: ['NPM_REG_PROV_ABSENT'],
      packages: locked({ dev: true }, { devDependencies: { widget: '^1.0.0' } }),
      caches: { widget: { packument: doc('1.0.0') } },
    });
    const miss = await run({ flags: ['NPM_REG_PROV_ABSENT'], packages: locked() });
    expect(attested).toEqual([]);
    expect(signed).toEqual([]);
    expect(dev).toEqual([]);
    expect(miss).toEqual([]);
  });
});

describe('phase 155 builder', () => {
  it('flags a builder identity that is not in the allowlist', async () => {
    const id = 'https://evil.example/builder';
    const findings = await run({
      flags: ['NPM_REG_BUILDER'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', {
            dist: { integrity: 'sha512-same', tarball: TARBALL, attestations: { builder: { id } } },
          }),
        },
      },
    });
    expectOnly(findings, 'DEPS-REG-BUILDER-001', 'medium');
    expect(findings[0]?.message).toContain(id);
  });

  it('does not flag a version with no attestation', async () => {
    const findings = await run({
      flags: ['NPM_REG_BUILDER'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0') } },
    });
    expect(findings).toEqual([]);
  });
});

describe('phase 156 attested repo', () => {
  it('flags an attested source repo that differs from the previous cache', async () => {
    const findings = await run({
      flags: ['NPM_REG_REPO'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', {
            dist: {
              integrity: 'sha512-same',
              tarball: TARBALL,
              attestations: { source: 'https://github.com/evil/widget' },
            },
          }),
          previous: { repo: 'https://github.com/acme/widget' },
        },
      },
    });
    expectOnly(findings, 'DEPS-REG-REPO-001', 'medium');
  });

  it('does not flag the same repo, a missing attestation, or the first sight', async () => {
    const same = await run({
      flags: ['NPM_REG_REPO'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', {
            dist: {
              integrity: 'sha512-same',
              tarball: TARBALL,
              attestations: { source: 'git+https://github.com/acme/widget.git' },
            },
          }),
          previous: { repo: 'https://github.com/acme/widget' },
        },
      },
    });
    const bare = await run({
      flags: ['NPM_REG_REPO'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0'),
          previous: { repo: 'https://github.com/acme/widget' },
        },
      },
    });
    const first = await run({
      flags: ['NPM_REG_REPO'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', {
            dist: { integrity: 'sha512-same', tarball: TARBALL, attestations: { source: 'https://github.com/acme/widget' } },
          }),
        },
      },
    });
    expect(same).toEqual([]);
    expect(bare).toEqual([]);
    expect(first).toEqual([]);
  });
});

describe('phase 157 subject', () => {
  it('flags an attestation subject version that is not the locked version', async () => {
    const findings = await run({
      flags: ['NPM_REG_SUBJECT'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', {
            dist: {
              integrity: 'sha512-same',
              tarball: TARBALL,
              attestations: { subject: [{ name: 'widget', version: '9.9.9' }] },
            },
          }),
        },
      },
    });
    expectOnly(findings, 'DEPS-REG-SUBJECT-001', 'high');
  });

  it('does not flag a matching subject or a packument with no subject', async () => {
    const match = await run({
      flags: ['NPM_REG_SUBJECT'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', {
            dist: {
              integrity: 'sha512-same',
              tarball: TARBALL,
              attestations: { subject: [{ name: 'widget@1.0.0' }] },
            },
          }),
        },
      },
    });
    const none = await run({
      flags: ['NPM_REG_SUBJECT'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0') } },
    });
    expect(match).toEqual([]);
    expect(none).toEqual([]);
  });
});

describe('phase 158 time', () => {
  it('flags a missing, unparseable, or future packument time', async () => {
    const missing = await run({
      flags: ['NPM_REG_TIME'],
      packages: locked(),
      caches: { widget: { packument: { versions: { '1.0.0': versionDoc() } } } },
    });
    const bad = await run({
      flags: ['NPM_REG_TIME'],
      packages: locked(),
      caches: { widget: { packument: { versions: { '1.0.0': versionDoc() }, time: { '1.0.0': 'yesterday' } } } },
    });
    const future = await run({
      flags: ['NPM_REG_TIME'],
      packages: locked(),
      caches: { widget: { packument: { versions: { '1.0.0': versionDoc() }, time: { '1.0.0': hoursAgo(-24) } } } },
    });
    expectOnly(missing, 'DEPS-REG-TIME-001', 'medium');
    expectOnly(bad, 'DEPS-REG-TIME-001', 'medium');
    expectOnly(future, 'DEPS-REG-TIME-001', 'medium');
  });

  it('does not flag a past timestamp, including a young one', async () => {
    const past = await run({
      flags: ['NPM_REG_TIME'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0') } },
    });
    const young = await run({
      flags: ['NPM_REG_TIME'],
      packages: locked(),
      caches: { widget: { packument: { versions: { '1.0.0': versionDoc() }, time: { '1.0.0': hoursAgo(1) } } } },
    });
    expect(past).toEqual([]);
    expect(young).toEqual([]);
  });
});

describe('phase 159 transitive age', () => {
  it('flags a young transitive production package and not a direct one', async () => {
    const packages = {
      '': { dependencies: { parent: '1.0.0' } },
      'node_modules/parent': { version: '1.0.0', dependencies: { child: '1.0.0' } },
      'node_modules/child': { version: '1.0.0' },
    };
    const young = hoursAgo(1);
    const findings = await run({
      flags: ['NPM_REG_TRANSITIVE_AGE'],
      packages,
      manifest: JSON.stringify({ dependencies: { parent: '1.0.0' } }),
      caches: {
        parent: { packument: { versions: { '1.0.0': {} }, time: { '1.0.0': young } } },
        child: { packument: { versions: { '1.0.0': {} }, time: { '1.0.0': young } } },
      },
    });
    expectOnly(findings, 'DEPS-REG-AGE-001', 'low');
    expect(findings[0]?.snippet).toBe('child@1.0.0');
  });

  it('does not flag an older transitive package, a direct dependency, or missing time', async () => {
    const packages = {
      '': { dependencies: { parent: '1.0.0' }, devDependencies: { tool: '1.0.0' } },
      'node_modules/parent': { version: '1.0.0' },
      'node_modules/tool': { version: '1.0.0', dev: true },
      'node_modules/old': { version: '1.0.0' },
    };
    const findings = await run({
      flags: ['NPM_REG_TRANSITIVE_AGE'],
      packages,
      manifest: JSON.stringify({ dependencies: { parent: '1.0.0' }, devDependencies: { tool: '1.0.0' } }),
      caches: {
        parent: { packument: { versions: { '1.0.0': {} }, time: { '1.0.0': hoursAgo(1) } } },
        tool: { packument: { versions: { '1.0.0': {} }, time: { '1.0.0': hoursAgo(1) } } },
        old: { packument: { versions: { '1.0.0': {} }, time: { '1.0.0': OLD } } },
      },
    });
    expect(findings.filter((finding) => finding.ruleId === 'DEPS-REG-AGE-001')).toEqual([]);
  });
});

describe('phase 160 install script', () => {
  it('emits one row when the packument lists an install script', async () => {
    const findings = await run({
      flags: ['NPM_REG_INSTALLSCRIPT'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', { hasInstallScript: true, scripts: { install: 'node install.js' } }),
        },
      },
    });
    expectOnly(findings, 'DEPS-REG-INSTALLSCRIPT-001', 'info');
  });

  it('does not flag a version with no install scripts', async () => {
    const findings = await run({
      flags: ['NPM_REG_INSTALLSCRIPT'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', { scripts: { test: 'node test.js' } }) } },
    });
    expect(findings).toEqual([]);
  });
});

describe('phase 161 signatures', () => {
  it('flags an empty signatures array', async () => {
    const findings = await run({
      flags: ['NPM_REG_SIGNATURES'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', { dist: { signatures: [], integrity: 'sha512-same', tarball: TARBALL } }) } },
    });
    expectOnly(findings, 'DEPS-REG-SIGNATURES-001', 'info');
  });

  it('does not flag a non-empty array or a missing signatures key', async () => {
    const filled = await run({
      flags: ['NPM_REG_SIGNATURES'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', { dist: { signatures: [{ keyid: 'k' }], integrity: 'sha512-same', tarball: TARBALL } }) } },
    });
    const absent = await run({
      flags: ['NPM_REG_SIGNATURES'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0') } },
    });
    expect(filled).toEqual([]);
    expect(absent).toEqual([]);
  });
});

describe('phase 162 engines', () => {
  it('flags engine ranges that do not intersect', async () => {
    const findings = await run({
      flags: ['NPM_REG_ENGINES'],
      packages: locked(),
      manifest: JSON.stringify({ dependencies: { widget: '^1.0.0' }, engines: { node: '^18.0.0' } }),
      caches: { widget: { packument: doc('1.0.0', { engines: { node: '^20.0.0' } }) } },
    });
    expectOnly(findings, 'DEPS-REG-ENGINES-001', 'medium');
  });

  it('does not flag an overlap or an unparseable range', async () => {
    const overlap = await run({
      flags: ['NPM_REG_ENGINES'],
      packages: locked(),
      manifest: JSON.stringify({
        dependencies: { widget: '^1.0.0' },
        engines: { node: '>=18.0.0 <21.0.0' },
      }),
      caches: { widget: { packument: doc('1.0.0', { engines: { node: '^20.0.0' } }) } },
    });
    const fuzzy = await run({
      flags: ['NPM_REG_ENGINES'],
      packages: locked(),
      manifest: JSON.stringify({ dependencies: { widget: '^1.0.0' }, engines: { node: '>=18' } }),
      caches: { widget: { packument: doc('1.0.0', { engines: { node: '^18.0.0' } }) } },
    });
    expect(overlap).toEqual([]);
    expect(fuzzy).toEqual([]);
  });
});

describe('phase 163 drift', () => {
  it('names the greatest in-range packument version and no other version', async () => {
    const findings = await run({
      flags: ['NPM_REG_DRIFT'],
      packages: locked(),
      manifest: JSON.stringify({ dependencies: { widget: '^1.0.0' } }),
      caches: {
        widget: {
          packument: {
            time: { '1.0.0': OLD, '1.2.0': OLD, '2.0.0': OLD },
            versions: { '1.0.0': versionDoc(), '1.2.0': versionDoc(), '2.0.0': versionDoc() },
          },
        },
      },
    });
    expectOnly(findings, 'DEPS-REG-DRIFT-001', 'info');
    expect(findings[0]?.message).toContain('1.2.0');
    expect(findings[0]?.message).not.toContain('9.9.9');
    expect(findings[0]?.message).not.toContain('2.0.0');
  });

  it('does not flag the greatest satisfying version', async () => {
    const findings = await run({
      flags: ['NPM_REG_DRIFT'],
      packages: locked(),
      manifest: JSON.stringify({ dependencies: { widget: '^1.0.0' } }),
      caches: { widget: { packument: doc('1.0.0') } },
    });
    expect(findings).toEqual([]);
  });
});

describe('phase 164 dependency range', () => {
  it('flags a locked dependency that misses the packument range', async () => {
    const packages = {
      '': { dependencies: { parent: '1.0.0' } },
      'node_modules/parent': { version: '1.0.0' },
      'node_modules/child': { version: '1.0.0' },
    };
    const findings = await run({
      flags: ['NPM_REG_DEPS'],
      packages,
      manifest: JSON.stringify({ dependencies: { parent: '1.0.0' } }),
      caches: { parent: { packument: doc('1.0.0', { dependencies: { child: '^2.0.0' } }) } },
    });
    expectOnly(findings, 'DEPS-REG-DEPS-001', 'medium');
    expect(findings[0]?.message).toContain('child@^2.0.0');
  });

  it('does not flag a satisfying lock or a range the helper cannot parse', async () => {
    const packages = {
      '': { dependencies: { parent: '1.0.0' } },
      'node_modules/parent': { version: '1.0.0' },
      'node_modules/child': { version: '2.1.0' },
    };
    const ok = await run({
      flags: ['NPM_REG_DEPS'],
      packages,
      manifest: JSON.stringify({ dependencies: { parent: '1.0.0' } }),
      caches: { parent: { packument: doc('1.0.0', { dependencies: { child: '^2.0.0' } }) } },
    });
    const git = await run({
      flags: ['NPM_REG_DEPS'],
      packages,
      manifest: JSON.stringify({ dependencies: { parent: '1.0.0' } }),
      caches: { parent: { packument: doc('1.0.0', { dependencies: { child: 'github:acme/child' } }) } },
    });
    expect(ok).toEqual([]);
    expect(git).toEqual([]);
  });
});

describe('phase 165 peers', () => {
  it('flags a required peer that is absent from the lock', async () => {
    const findings = await run({
      flags: ['NPM_REG_PEER'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', { peerDependencies: { react: '^18.0.0' } }) } },
    });
    expectOnly(findings, 'DEPS-REG-PEER-001', 'medium');
  });

  it('does not flag a locked peer or an optional peer that is absent', async () => {
    const present = await run({
      flags: ['NPM_REG_PEER'],
      packages: {
        '': { dependencies: { widget: '^1.0.0' } },
        'node_modules/widget': { version: '1.0.0' },
        'node_modules/react': { version: '18.2.0' },
      },
      caches: { widget: { packument: doc('1.0.0', { peerDependencies: { react: '^18.0.0' } }) } },
    });
    const optional = await run({
      flags: ['NPM_REG_PEER'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', {
            peerDependencies: { react: '^18.0.0' },
            peerDependenciesMeta: { react: { optional: true } },
          }),
        },
      },
    });
    expect(present).toEqual([]);
    expect(optional).toEqual([]);
  });
});

describe('phase 166 bin path', () => {
  it('flags a bin target that escapes the package', async () => {
    const findings = await run({
      flags: ['NPM_REG_BIN'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', { bin: { cli: '../evil.js', win: 'C:\\evil.js', slip: 'bin\\..\\x.js' } }),
        },
      },
    });
    expect(ids(findings)).toEqual(['DEPS-REG-BIN-001', 'DEPS-REG-BIN-001', 'DEPS-REG-BIN-001']);
    expect(findings.every((finding) => finding.severity === 'high')).toBe(true);
  });

  it('does not flag bin/cli.js', async () => {
    const findings = await run({
      flags: ['NPM_REG_BIN'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', { bin: 'bin/cli.js' }) } },
    });
    expect(findings).toEqual([]);
  });
});

describe('phase 167 repository host', () => {
  it('flags a different host and a repository field that disappeared', async () => {
    const changed = await run({
      flags: ['NPM_REG_REPOSITORY'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', {}, { repository: { type: 'git', url: 'git+https://gitlab.com/acme/widget.git' } }),
          previous: { repositoryHost: 'github.com' },
        },
      },
    });
    const gone = await run({
      flags: ['NPM_REG_REPOSITORY'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0'), previous: { repositoryHost: 'github.com' } } },
    });
    expectOnly(changed, 'DEPS-REG-REPOSITORY-001', 'info');
    expectOnly(gone, 'DEPS-REG-REPOSITORY-001', 'info');
  });

  it('does not flag the same host or the first sight', async () => {
    const same = await run({
      flags: ['NPM_REG_REPOSITORY'],
      packages: locked(),
      caches: {
        widget: {
          packument: doc('1.0.0', {}, { repository: 'github:acme/widget' }),
          previous: { repositoryHost: 'github.com' },
        },
      },
    });
    const first = await run({
      flags: ['NPM_REG_REPOSITORY'],
      packages: locked(),
      caches: { widget: { packument: doc('1.0.0', {}, { repository: { url: 'https://github.com/acme/widget' } }) } },
    });
    expect(same).toEqual([]);
    expect(first).toEqual([]);
  });
});

describe('cache and flags', () => {
  it('returns nothing when no lane flag is set', async () => {
    const findings = await run({
      flags: [],
      packages: locked({ integrity: 'sha512-lock' }),
      caches: { widget: { packument: doc('1.0.0', { dist: { integrity: 'sha512-reg', tarball: TARBALL } }) } },
    });
    expect(findings).toEqual([]);
  });

  it('does not fetch, does not write the cache, and reads a scoped name', async () => {
    const original = globalThis.fetch;
    globalThis.fetch = () => Promise.reject(new Error('network'));
    try {
      const cwd = await tempDir();
      process.env[envFlag('NPM_REG_INTEGRITY')] = '1';
      const name = '@acme/widget';
      const packument = doc('1.0.0', { dist: { integrity: 'sha512-reg', tarball: TARBALL } });
      await writeCache(cwd, name, packument);
      const path = join(cwd, 'registry', '@acme__widget.json');
      const before = await readFile(path, 'utf8');
      const findings = await laneFindings({
        cwd,
        files: ['package.json', 'package-lock.json'],
        manifestRaw: JSON.stringify({ dependencies: { [name]: '1.0.0' } }),
        lockTexts: {
          'package-lock.json': JSON.stringify({
            packages: {
              '': { dependencies: { [name]: '1.0.0' } },
              'node_modules/@acme/widget': { version: '1.0.0', integrity: 'sha512-lock', resolved: TARBALL },
            },
          }),
        },
        cacheDir: cwd,
        offline: false,
      });
      expect(ids(findings)).toEqual(['DEPS-REG-INTEGRITY-001']);
      expect(await readFile(path, 'utf8')).toBe(before);
    } finally {
      globalThis.fetch = original;
    }
  });

  it('reads previous maintainers from prev-<name>.json', async () => {
    const cwd = await tempDir();
    process.env[envFlag('NPM_REG_MAINTAINER')] = '1';
    await writeFile(join(cwd, 'registry', 'widget.json'), JSON.stringify({
      fetchedAt: OLD,
      packument: doc('1.0.0', {}, { maintainers: [{ name: 'bob' }] }),
    }));
    await writeFile(join(cwd, 'registry', 'prev-widget.json'), JSON.stringify({ maintainers: ['alice'] }));
    const findings = await laneFindings({
      cwd,
      files: ['package-lock.json'],
      lockTexts: { 'package-lock.json': JSON.stringify({ packages: locked() }) },
      cacheDir: cwd,
      offline: true,
    });
    expectOnly(findings, 'DEPS-REG-MAINTAINER-001', 'medium');
  });
});

describe('age window config', () => {
  it('uses deps.minReleaseAgeHours and otherwise 72', async () => {
    const packages = {
      '': { dependencies: { parent: '1.0.0' } },
      'node_modules/parent': { version: '1.0.0', dependencies: { child: '1.0.0' } },
      'node_modules/child': { version: '1.0.0' },
    };
    const narrow = await run({
      flags: ['NPM_REG_TRANSITIVE_AGE'],
      packages,
      manifest: JSON.stringify({ dependencies: { parent: '1.0.0' } }),
      config: JSON.stringify({ deps: { minReleaseAgeHours: 1 } }),
      caches: { child: { packument: { versions: { '1.0.0': {} }, time: { '1.0.0': hoursAgo(2) } } } },
    });
    const wide = await run({
      flags: ['NPM_REG_TRANSITIVE_AGE'],
      packages,
      manifest: JSON.stringify({ dependencies: { parent: '1.0.0' } }),
      caches: { child: { packument: { versions: { '1.0.0': {} }, time: { '1.0.0': hoursAgo(2) } } } },
    });
    expect(narrow).toEqual([]);
    expectOnly(wide, 'DEPS-REG-AGE-001', 'low');
  });
});

describe('R12 clean-app', () => {
  it('emits none of these ids when every flag is on and the registry cache is missing', async () => {
    for (const name of FLAGS) {process.env[envFlag(name)] = '1';}
    const cache = await tempDir();
    const configPath = join(cache, 'scan-config.json');
    await writeFile(configPath, JSON.stringify({ deps: { cacheDir: cache } }));
    const result = await scan({
      cwd: join(process.cwd(), 'test', 'fixtures', 'clean-app'),
      modules: ['deps'],
      offline: true,
      configPath,
    });
    const ours = new Set<string>(RULE_IDS);
    expect(result.findings.filter((finding) => ours.has(finding.ruleId))).toEqual([]);
  });
});

describe('scan wiring', () => {
  it('reports lock integrity through scan()', async () => {
    process.env[envFlag('NPM_REG_INTEGRITY')] = '1';
    const cwd = await tempDir();
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ dependencies: { widget: '1.0.0' } }));
    await writeFile(join(cwd, 'package-lock.json'), JSON.stringify({
      name: 'app',
      lockfileVersion: 3,
      packages: locked({ integrity: 'sha512-lock' }),
    }));
    await writeFile(join(cwd, 'fullshield.config.json'), JSON.stringify({ deps: { cacheDir: cwd } }));
    await writeCache(cwd, 'widget', doc('1.0.0', { dist: { integrity: 'sha512-reg', tarball: TARBALL } }));
    const result = await scan({ cwd, modules: ['deps'], offline: true });
    expect(result.findings.some((finding) => finding.ruleId === 'DEPS-REG-INTEGRITY-001')).toBe(true);
  });
});
