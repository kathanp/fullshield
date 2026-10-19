import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { parseLockfile } from '../modules/deps/lockfile.js';
import { exactPinsFromManifest } from '../modules/deps/pins.js';

const LOCKFILE_NAMES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;

export interface SpdxOptions {
  created?: string;
  cyclonedxPath?: string;
}

interface SpdxPackage {
  SPDXID: string;
  name: string;
  versionInfo: string;
  downloadLocation: 'NOASSERTION';
  filesAnalyzed: false;
  licenseConcluded: 'NOASSERTION';
  licenseDeclared?: string;
  externalRefs: Array<{ referenceCategory: 'PACKAGE-MANAGER'; referenceType: 'purl'; referenceLocator: string }>;
}

export async function buildSpdx(cwd: string, options: SpdxOptions = {}): Promise<Record<string, unknown>> {
  let name = 'app';
  let version = '0.0.0';
  let manifest: Record<string, unknown> = {};
  try {
    manifest = JSON.parse(await readFile(join(cwd, 'package.json'), 'utf8')) as Record<string, unknown>;
    if (typeof manifest.name === 'string') name = manifest.name;
    if (typeof manifest.version === 'string') version = manifest.version;
  } catch {
    manifest = {};
  }
  let packages: Array<{ name: string; version: string }> = [];
  for (const candidate of LOCKFILE_NAMES) {
    try {
      packages = parseLockfile(candidate, await readFile(join(cwd, candidate), 'utf8')).map((item) => ({
        name: item.name,
        version: item.version,
      }));
      break;
    } catch {
      continue;
    }
  }
  if (packages.length === 0) packages = exactPinsFromManifest(manifest);
  packages.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  const created =
    options.created ??
    (process.env.SOURCE_DATE_EPOCH !== undefined
      ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000).toISOString()
      : '1970-01-01T00:00:00.000Z');
  const document: SpdxPackage[] = packages.map((item) => ({
    SPDXID: `SPDXRef-Package-${item.name.replace(/[^A-Za-z0-9.-]/g, '-')}-${item.version}`,
    name: item.name,
    versionInfo: item.version,
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION',
    externalRefs: [
      {
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: `pkg:npm/${item.name}@${item.version}`,
      },
    ],
  }));
  const relationships = document.map((item) => ({
    spdxElementId: 'SPDXRef-DOCUMENT',
    relatedSpdxElement: item.SPDXID,
    relationshipType: 'DEPENDS_ON',
  }));
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name,
    documentNamespace: `https://fullshield.local/spdx/${name}/${version}`,
    creationInfo: {
      created,
      creators: ['Tool: fullshield'],
    },
    packages: document,
    relationships,
    ...(options.cyclonedxPath !== undefined
      ? { comment: `Vulnerability data is in ${options.cyclonedxPath}` }
      : {}),
  };
}

export function spdxErrors(doc: Record<string, unknown>): string[] {
  const errors: string[] = [];
  if (doc.spdxVersion !== 'SPDX-2.3') errors.push('spdxVersion');
  if (doc.dataLicense !== 'CC0-1.0') errors.push('dataLicense');
  if (doc.SPDXID !== 'SPDXRef-DOCUMENT') errors.push('SPDXID');
  if (typeof doc.name !== 'string') errors.push('name');
  if (typeof doc.documentNamespace !== 'string') errors.push('documentNamespace');
  const creation = doc.creationInfo;
  if (creation === null || typeof creation !== 'object' || typeof (creation as { created?: string }).created !== 'string') {
    errors.push('creationInfo.created');
  }
  if (!Array.isArray(doc.packages) || !Array.isArray(doc.relationships)) errors.push('packages');
  return errors;
}
