import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Finding } from '../../../core/finding.js';
import { laneFindings as laneA, laneRows as rowsA } from './lane-a.js';
import { laneFindings as laneB, laneRows as rowsB } from './lane-b.js';
import { laneFindings as laneC, laneRows as rowsC } from './lane-c.js';
import { laneFindings as laneD, laneRows as rowsD } from './lane-d.js';
import { laneFindings as laneE, laneRows as rowsE } from './lane-e.js';
import { laneFindings as laneF, laneRows as rowsF } from './lane-f.js';
import { laneFindings as laneG, laneRows as rowsG } from './lane-g.js';
import { laneFindings as laneH, laneRows as rowsH } from './lane-h.js';
import { NPM_LOCK_NAMES } from './lockpick.js';
import type { NpmDepthInput, NpmDepthRow } from './types.js';

export { pickNpmLock } from './lockpick.js';

const lanes = [laneA, laneB, laneC, laneD, laneE, laneF, laneG, laneH];

export const npmDepthRows: readonly NpmDepthRow[] = [
  ...rowsA,
  ...rowsB,
  ...rowsC,
  ...rowsD,
  ...rowsE,
  ...rowsF,
  ...rowsG,
  ...rowsH,
];

function npmDepthEnabled(): boolean {
  for (const [key, value] of Object.entries(process.env)) {
    if (key.startsWith('FULLSHIELD_EXPERIMENTAL_NPM_') && value === '1') {return true;}
  }
  return false;
}

export async function readLockTexts(
  cwd: string,
  files: readonly string[],
): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const name of NPM_LOCK_NAMES) {
    if (!files.includes(name)) {continue;}
    try {
      out[name] = await readFile(join(cwd, name), 'utf8');
    } catch {
      // unreadable lockfile is not a depth finding
    }
  }
  return out;
}

export async function npmDepthFindings(input: NpmDepthInput): Promise<Finding[]> {
  if (!npmDepthEnabled()) {return [];}
  const groups = await Promise.all(lanes.map((lane) => lane(input)));
  return groups.flat();
}
