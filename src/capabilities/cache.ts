import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { isCapabilityName, type CapabilityName } from './names.js';

function capabilityCachePath(cacheDir: string, integrity: string): string {
  const safe = integrity.replace(/[^A-Za-z0-9]/g, '_');
  return join(cacheDir, 'capabilities', `${safe}.json`);
}

export function readCached(cacheDir: string, integrity: string | undefined): CapabilityName[] | undefined {
  if (integrity === undefined) {return undefined;}
  try {
    const raw = JSON.parse(readFileSync(capabilityCachePath(cacheDir, integrity), 'utf8')) as {
      capabilities?: unknown;
    };
    if (!Array.isArray(raw.capabilities)) {return undefined;}
    return raw.capabilities.filter(isCapabilityName);
  } catch {
    return undefined;
  }
}

export function writeCached(cacheDir: string, integrity: string, capabilities: readonly CapabilityName[]): void {
  const path = capabilityCachePath(cacheDir, integrity);
  mkdirSync(join(cacheDir, 'capabilities'), { recursive: true });
  const body = { integrity, capabilities: [...capabilities].sort() };
  writeFileSync(path, `${JSON.stringify(body)}\n`);
}
