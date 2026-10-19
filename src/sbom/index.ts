import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { scan } from '../core/engine.js';
import { parseLockfile } from '../modules/deps/lockfile.js';
import { exactPinsFromManifest } from '../modules/deps/pins.js';
import { renderCycloneDx, type SbomComponent } from './cyclonedx.js';

const LOCKFILE_NAMES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;

export async function buildSbom(cwd: string, options: { includeReach?: boolean } = {}): Promise<Record<string, unknown>> {
  const result = await scan({ cwd, modules: ['deps'] });
  let name = 'app';
  let version = '0.0.0';
  let manifest: Record<string, unknown> = {};
  try {
    manifest = JSON.parse(await readFile(join(cwd, 'package.json'), 'utf8')) as Record<string, unknown>;
    if (typeof manifest.name === 'string') name = manifest.name;
    if (typeof manifest.version === 'string') version = manifest.version;
  } catch {
    // package.json is optional for SBOM of a lockfile-only tree
  }

  let components: SbomComponent[] = [];
  for (const candidate of LOCKFILE_NAMES) {
    try {
      const contents = await readFile(join(cwd, candidate), 'utf8');
      components = parseLockfile(candidate, contents).map((p) => ({
        name: p.name,
        version: p.version,
      }));
      break;
    } catch {
      // try the next lockfile name
    }
  }
  if (components.length === 0) {
    components = exactPinsFromManifest(manifest).map((p) => ({ name: p.name, version: p.version }));
  }
  return renderCycloneDx({
    name,
    version,
    components,
    findings: result.findings,
    includeReach: options.includeReach === true,
  });
}
