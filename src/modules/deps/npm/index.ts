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
import { loadNpmFacts, runWithFacts } from './facts.js';
import { NPM_LOCK_NAMES } from './lockpick.js';
import type { NpmDepthInput, NpmDepthRow, NpmFacts } from './types.js';

export { pickNpmLock } from './lockpick.js';

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

function factsInput(facts: NpmFacts): NpmDepthInput {
  return {
    cwd: facts.cwd,
    files: facts.files,
    manifestRaw: facts.manifestRaw,
    lockTexts: facts.lockTexts,
    cacheDir: facts.cacheDir,
    offline: facts.offline,
    facts,
  };
}

/** Lane checks as pure functions of the facts built for this scan. */
const npmGroupChecks = {
  NPM_LOCK: (facts: NpmFacts) => runWithFacts(facts, () => laneA(factsInput(facts))),
  NPM_MANIFEST: (facts: NpmFacts) => runWithFacts(facts, () => laneB(factsInput(facts))),
  NPM_REGISTRY: (facts: NpmFacts) => runWithFacts(facts, () => laneC(factsInput(facts))),
  NPM_TARBALL: (facts: NpmFacts) => runWithFacts(facts, () => laneD(factsInput(facts))),
  NPM_SCRIPTS: (facts: NpmFacts) => runWithFacts(facts, () => laneE(factsInput(facts))),
  NPM_NAMES: (facts: NpmFacts) => runWithFacts(facts, () => laneF(factsInput(facts))),
  NPM_GRAPH: (facts: NpmFacts) => runWithFacts(facts, () => laneG(factsInput(facts))),
  NPM_ADVISORY: (facts: NpmFacts) => runWithFacts(facts, () => laneH(factsInput(facts))),
};

/**
 * Build `NpmFacts` once, then run the phase 108–250 lane functions.
 * Group flags select the same functions as the per-phase aliases (`npmFlag`).
 * With every `FULLSHIELD_EXPERIMENTAL_NPM_*` flag off, this returns `[]`.
 */
export async function npmDepthFindings(input: NpmDepthInput): Promise<Finding[]> {
  if (!npmDepthEnabled()) {return [];}
  const facts = input.facts ?? await loadNpmFacts(input);
  const groups = await Promise.all(Object.values(npmGroupChecks).map((check) => check(facts)));
  return groups.flat();
}
