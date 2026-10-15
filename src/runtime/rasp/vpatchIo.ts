import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { findingsToVpatches, type VirtualPatch, type VpatchFinding } from './vpatch.js';

export function emitVirtualPatches(findings: VpatchFinding[], outPath: string): VirtualPatch[] {
  const patches = findingsToVpatches(findings);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify({ patches }, null, 2)}\n`, 'utf8');
  return patches;
}

export function loadVirtualPatches(path: string): VirtualPatch[] {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as { patches?: VirtualPatch[] } | VirtualPatch[];
  return Array.isArray(raw) ? raw : (raw.patches ?? []);
}
