import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Finding } from '../../core/finding.js';
import { loadModelPacks, modelSuppressReason } from './models.js';
import { typeSuppressReason } from './type-receivers.js';

export async function applyExperimentalSuppressions(
  cwd: string,
  files: readonly string[],
  findings: Finding[],
): Promise<{ findings: Finding[]; suppressed: Finding[] }> {
  const modelsOn = process.env.FULLSHIELD_EXPERIMENTAL_MODELS === '1';
  const typesOn = process.env.FULLSHIELD_EXPERIMENTAL_TYPES === '1';
  const kept: Finding[] = [];
  const suppressed: Finding[] = [];
  const texts = new Map<string, string>();
  for (const finding of findings) {
    if (finding.file !== undefined && !texts.has(finding.file)) {
      try {
        texts.set(finding.file, await readFile(join(cwd, finding.file), 'utf8'));
      } catch {
        texts.set(finding.file, '');
      }
    }
  }
  let manifest = '';
  try {
    manifest = await readFile(join(cwd, 'package.json'), 'utf8');
  } catch {
    manifest = '';
  }
  const packs = modelsOn ? await loadModelPacks() : [];
  const versions = dependencyVersions(manifest);
  for (const finding of findings) {
    const source = finding.file !== undefined ? texts.get(finding.file) ?? '' : '';
    if (modelsOn) {
      const reason = modelSuppressReason(finding, source, packs, versions);
      if (reason !== undefined) {
        suppressed.push({ ...finding, suppressedBy: reason });
        continue;
      }
    }
    if (typesOn && finding.file !== undefined) {
      const reason = await typeSuppressReason(cwd, files, finding);
      if (reason !== undefined) {
        suppressed.push({ ...finding, suppressedBy: reason });
        continue;
      }
    }
    kept.push(finding);
  }
  return { findings: kept, suppressed };
}

function dependencyVersions(manifest: string): Map<string, string> {
  const versions = new Map<string, string>();
  if (manifest.length === 0) return versions;
  try {
    const parsed = JSON.parse(manifest) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    for (const table of [parsed.dependencies, parsed.devDependencies]) {
      for (const [name, range] of Object.entries(table ?? {})) {
        const version = range.replace(/^[\^~>=<]+/, '');
        if (/^\d+\.\d+\.\d+/.test(version)) versions.set(name, version);
      }
    }
  } catch {
    return versions;
  }
  return versions;
}
