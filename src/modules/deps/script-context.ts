import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { LockfileGraph } from './lockfile.js';
import { npmFlag } from './npm/types.js';

export interface ScriptReachInput {
  scripts?: Readonly<Record<string, string>>;
  bins?: ReadonlyMap<string, string | Readonly<Record<string, string>>>;
}

function scriptMap(value: unknown): Record<string, string> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {return undefined;}
  const scripts: Record<string, string> = {};
  for (const [key, body] of Object.entries(value)) {
    if (typeof body === 'string') {scripts[key] = body;}
  }
  return scripts;
}

function binField(value: unknown): string | Record<string, string> | undefined {
  if (typeof value === 'string') {return value;}
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {return undefined;}
  const bin: Record<string, string> = {};
  for (const [key, path] of Object.entries(value)) {
    if (typeof path === 'string') {bin[key] = path;}
  }
  return Object.keys(bin).length > 0 ? bin : undefined;
}

async function readDepBin(cwd: string, name: string): Promise<string | Record<string, string> | undefined> {
  try {
    const raw = await readFile(join(cwd, 'node_modules', name, 'package.json'), 'utf8');
    const doc = JSON.parse(raw) as { bin?: unknown };
    return binField(doc.bin);
  } catch {
    return undefined;
  }
}

/** Flag off leaves scripts unread. A missing installed bin stays `not-imported`. */
export async function scriptReachContext(cwd: string, graph: LockfileGraph): Promise<ScriptReachInput> {
  if (!npmFlag('NPM_REACH_BIN')) {return {};}
  let scripts: Record<string, string> | undefined;
  try {
    const raw = await readFile(join(cwd, 'package.json'), 'utf8');
    scripts = scriptMap((JSON.parse(raw) as { scripts?: unknown }).scripts);
  } catch {
    scripts = undefined;
  }
  const bins = new Map<string, string | Record<string, string>>();
  for (const name of [...graph.directProd, ...graph.directDev]) {
    const bin = await readDepBin(cwd, name);
    if (bin !== undefined) {bins.set(name, bin);}
  }
  return { scripts, bins };
}
