/**
 * Phase 396. Field-level virtual patches.
 * Off unless FULLSHIELD_EXPERIMENTAL_FIELDPATCH=1.
 * Patches are data. The default action is block. No source edit.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FIELDPATCH';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface FieldPatch {
  path: string;
  action?: 'strip' | 'block';
}

export interface PatchResult {
  body: Record<string, unknown>;
  status: number;
  logs: string[];
}

function clone(body: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(body)) as Record<string, unknown>;
}

function read(body: Record<string, unknown>, parts: readonly string[]): boolean {
  let current: unknown = body;
  for (const part of parts) {
    if (typeof current !== 'object' || current === null || !(part in (current as Record<string, unknown>))) {
      return false;
    }
    current = (current as Record<string, unknown>)[part];
  }
  return true;
}

function strip(body: Record<string, unknown>, parts: string[]): void {
  let current: Record<string, unknown> = body;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const key = parts[i];
    if (key === undefined) {
      return;
    }
    const next = current[key];
    if (typeof next !== 'object' || next === null) {
      return;
    }
    current = next as Record<string, unknown>;
  }
  const leaf = parts[parts.length - 1];
  if (leaf !== undefined) {
    delete current[leaf];
  }
}

export function applyFieldPatches(body: Record<string, unknown>, patches: readonly FieldPatch[]): PatchResult {
  if (!enabled()) {
    return { body, status: 200, logs: [] };
  }
  const next = clone(body);
  const logs: string[] = [];
  const logged = new Set<string>();
  for (const patch of patches) {
    const parts = patch.path.split('.').filter((part) => part !== '' && part !== 'body');
    const action = patch.action ?? 'block';
    if (!read(next, parts)) {
      if (!logged.has(patch.path)) {
        logged.add(patch.path);
        logs.push(`unknown field path ${patch.path}`);
      }
      continue;
    }
    if (action === 'block') {
      return { body: next, status: 403, logs };
    }
    strip(next, parts);
  }
  return { body: next, status: 200, logs };
}
