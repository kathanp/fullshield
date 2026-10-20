import { createRequire } from 'node:module';
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../src/cli/program.js';
import { buildSpdxSbom } from '../../../src/sbom/spdx.js';

const require = createRequire(import.meta.url);
const withLicense = join(process.cwd(), 'test', 'fixtures', 'spdx', 'with-license');
const withoutLicense = join(process.cwd(), 'test', 'fixtures', 'spdx', 'without-license');
const vulnerableApp = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');
const schemaPath = join(process.cwd(), 'test', 'schemas', 'spdx-2.3.schema.json');
const dirs: string[] = [];

interface SpdxPackage {
  SPDXID: string;
  name: string;
  versionInfo?: string;
  downloadLocation?: string;
  licenseDeclared?: string;
  licenseConcluded?: string;
  externalRefs?: Array<{ referenceCategory: string; referenceType: string; referenceLocator: string }>;
}

interface SpdxRelationship {
  spdxElementId: string;
  relationshipType: string;
  relatedSpdxElement: string;
}

interface SpdxDocument {
  spdxVersion: string;
  dataLicense: string;
  SPDXID: string;
  name: string;
  documentNamespace: string;
  creationInfo: { created: string; creators: string[] };
  packages: SpdxPackage[];
  relationships: SpdxRelationship[];
  annotations?: Array<{ annotationType: string; comment: string; annotationDate: string }>;
}

function asSpdx(doc: Record<string, unknown>): SpdxDocument {
  return doc as unknown as SpdxDocument;
}

function schemaErrors(doc: unknown): string[] {
  const Ajv = require('ajv') as new (opts: { allErrors: boolean; strict: boolean; validateSchema: boolean }) => {
    compile: (schema: unknown) => ((data: unknown) => boolean) & { errors?: Array<{ instancePath?: string; message?: string }> | null };
  };
  const ajv = new Ajv({ allErrors: true, strict: false, validateSchema: false });
  const validate = ajv.compile(JSON.parse(readFileSync(schemaPath, 'utf8')) as unknown);
  if (validate(doc)) return [];
  return (validate.errors ?? []).map((error) => `${error.instancePath ?? ''} ${error.message ?? ''}`.trim());
}

function packageNamed(doc: SpdxDocument, name: string): SpdxPackage {
  const found = doc.packages.find((pkg) => pkg.name === name);
  if (found === undefined) throw new Error(`missing package ${name}`);
  return found;
}

function dependsOn(doc: SpdxDocument, fromName: string, toName: string): boolean {
  const from = packageNamed(doc, fromName);
  const to = packageNamed(doc, toName);
  return doc.relationships.some(
    (rel) =>
      rel.relationshipType === 'DEPENDS_ON' &&
      rel.spdxElementId === from.SPDXID &&
      rel.relatedSpdxElement === to.SPDXID,
  );
}

async function runCli(args: string[], env: Record<string, string | undefined> = {}): Promise<{ out: string; err: string }> {
  const previous = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(env)) {
    previous.set(key, process.env[key]);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  const out: string[] = [];
  const err: string[] = [];
  try {
    const program = createProgram({
      out: (text) => out.push(text),
      err: (text) => err.push(text),
    });
    await program.parseAsync(['node', 'fullshield', ...args]);
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
  return { out: out.join('\n'), err: err.join('\n') };
}

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_SPDX;
  delete process.env.SOURCE_DATE_EPOCH;
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe('Phase 89 SPDX SBOM', () => {
  it('copies licenses that are present and emits lockfile DEPENDS_ON edges and PURLs', async () => {
    const doc = asSpdx(await buildSpdxSbom(withLicense, { created: '2020-01-01T00:00:00Z' }));
    expect(schemaErrors(doc)).toEqual([]);
    expect(doc.spdxVersion).toBe('SPDX-2.3');
    expect(doc.creationInfo.created).toBe('2020-01-01T00:00:00Z');
    expect(packageNamed(doc, 'spdx-positive').licenseDeclared).toBe('Apache-2.0');
    expect(packageNamed(doc, 'left-pad').licenseDeclared).toBe('MIT');
    expect(packageNamed(doc, 'custom').licenseDeclared).toBe('SEE LICENSE IN FILE');
    expect(packageNamed(doc, 'blank').licenseDeclared).toBe('NOASSERTION');
    expect(packageNamed(doc, 'blank').licenseConcluded).toBe('NOASSERTION');
    expect(packageNamed(doc, 'left-pad').downloadLocation).toBe(
      'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz',
    );
    expect(packageNamed(doc, 'blank').downloadLocation).toBe('NOASSERTION');
    const leftPad = packageNamed(doc, 'left-pad');
    expect(leftPad.externalRefs?.[0]).toMatchObject({
      referenceCategory: 'PACKAGE-MANAGER',
      referenceType: 'purl',
      referenceLocator: 'pkg:npm/left-pad@1.3.0',
    });
    expect(dependsOn(doc, 'spdx-positive', 'left-pad')).toBe(true);
    expect(dependsOn(doc, 'spdx-positive', 'dev-tool')).toBe(true);
    expect(dependsOn(doc, 'left-pad', 'blank')).toBe(true);
    const ids = doc.packages.map((pkg) => pkg.SPDXID);
    expect(ids).toEqual([...ids].sort());
    const relKeys = doc.relationships.map((rel) => `${rel.spdxElementId}|${rel.relationshipType}|${rel.relatedSpdxElement}`);
    expect(relKeys).toEqual([...relKeys].sort());
    expect(doc).not.toHaveProperty('vulnerabilities');
  });

  it('does not invent a license when package data has none or only an ambiguous list', async () => {
    const doc = asSpdx(await buildSpdxSbom(withoutLicense, { created: '2020-01-01T00:00:00Z' }));
    expect(schemaErrors(doc)).toEqual([]);
    for (const pkg of doc.packages) {
      expect(pkg.licenseDeclared).toBe('NOASSERTION');
      expect(pkg.licenseConcluded).toBe('NOASSERTION');
    }
    expect(JSON.stringify(doc)).not.toMatch(/MIT|Apache-2\.0|ISC|BSD|GPL/);
    expect(dependsOn(doc, 'other', 'mystery')).toBe(true);
  });

  it('reads an installed package.json license only for the locked version', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-spdx-installed-'));
    dirs.push(dir);
    await cp(withoutLicense, dir, { recursive: true });
    await mkdir(join(dir, 'node_modules', 'mystery'), { recursive: true });
    await writeFile(
      join(dir, 'node_modules', 'mystery', 'package.json'),
      JSON.stringify({ name: 'mystery', version: '1.0.0', license: 'MIT' }),
    );
    await mkdir(join(dir, 'node_modules', 'other'), { recursive: true });
    await writeFile(
      join(dir, 'node_modules', 'other', 'package.json'),
      JSON.stringify({ name: 'other', version: '9.9.9', license: 'GPL-3.0-only' }),
    );
    const doc = asSpdx(await buildSpdxSbom(dir, { created: '2020-01-01T00:00:00Z' }));
    expect(packageNamed(doc, 'mystery').licenseDeclared).toBe('MIT');
    expect(packageNamed(doc, 'other').licenseDeclared).toBe('NOASSERTION');
    expect(JSON.stringify(doc)).not.toContain('GPL-3.0-only');
  });

  it('is deterministic for --sbom-timestamp and SOURCE_DATE_EPOCH', async () => {
    const first = await buildSpdxSbom(withLicense, { created: '2020-01-01T00:00:00Z' });
    const second = await buildSpdxSbom(withLicense, { created: '2020-01-01T00:00:00.000Z' });
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    process.env.SOURCE_DATE_EPOCH = '1577836800';
    const fromEpoch = await buildSpdxSbom(withLicense, {});
    expect(asSpdx(fromEpoch).creationInfo.created).toBe('2020-01-01T00:00:00Z');
    expect(JSON.stringify(fromEpoch)).toBe(JSON.stringify(first));
    const flagged = await buildSpdxSbom(withLicense, { created: '2021-06-01T00:00:00Z' });
    expect(asSpdx(flagged).creationInfo.created).toBe('2021-06-01T00:00:00Z');
  });

  it('references a CycloneDX file only when that file is generated in the same run', async () => {
    const plain = asSpdx(await buildSpdxSbom(withLicense, { created: '2020-01-01T00:00:00Z' }));
    expect(plain.annotations).toBeUndefined();
    expect(JSON.stringify(plain)).not.toContain('CycloneDX');
    const linked = asSpdx(
      await buildSpdxSbom(withLicense, { created: '2020-01-01T00:00:00Z', cyclonedxFile: 'bom.cdx.json' }),
    );
    expect(linked.annotations?.[0]?.annotationType).toBe('OTHER');
    expect(linked.annotations?.[0]?.comment).toContain('bom.cdx.json');
    expect(linked.annotations?.[0]?.annotationDate).toBe('2020-01-01T00:00:00Z');
    expect(linked).not.toHaveProperty('vulnerabilities');
    expect(schemaErrors(linked)).toEqual([]);
  });

  it('validates SPDX 2.3 JSON for vulnerable-app and one bench app', async () => {
    const app = asSpdx(await buildSpdxSbom(vulnerableApp, { created: '2020-01-01T00:00:00Z' }));
    expect(schemaErrors(app)).toEqual([]);
    expect(app.packages.length).toBeGreaterThan(0);
    for (const pkg of app.packages) expect(pkg.licenseDeclared).toBe('NOASSERTION');
    const home = process.env.FULLSHIELD_BENCH_DIR ?? join(homedir(), 'fullshield-bench');
    const bench = join(home, 'vulnerable-node');
    expect(existsSync(join(bench, 'package-lock.json'))).toBe(true);
    const benchDoc = await buildSpdxSbom(bench, { created: '2020-01-01T00:00:00Z' });
    expect(schemaErrors(benchDoc)).toEqual([]);
    expect(asSpdx(benchDoc)).not.toHaveProperty('vulnerabilities');
  });

  it('keeps the SPDX schema test-only and rejects spdx unless the flag is set', async () => {
    const pkg = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8')) as { files: string[] };
    expect(pkg.files.some((entry) => entry.includes('test/schemas') || entry.includes('spdx-2.3'))).toBe(false);
    expect(existsSync(schemaPath)).toBe(true);
    const refused = await runCli(['sbom', withLicense, '--format', 'spdx']);
    expect(refused.err).toMatch(/unsupported SBOM format/i);
    const dir = await mkdtemp(join(tmpdir(), 'fullshield-spdx-cli-'));
    dirs.push(dir);
    const out = join(dir, 'sbom.spdx.json');
    const enabled = await runCli(
      ['sbom', withLicense, '--format', 'spdx', '--sbom-timestamp', '2020-01-01T00:00:00Z', '--out', out],
      { FULLSHIELD_EXPERIMENTAL_SPDX: '1' },
    );
    expect(enabled.err).toBe('');
    const written = JSON.parse(await readFile(out, 'utf8')) as SpdxDocument;
    expect(schemaErrors(written)).toEqual([]);
    expect(written.creationInfo.created).toBe('2020-01-01T00:00:00Z');
  });
});
