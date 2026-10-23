/**
 * Phase 381. RASP hooks generated from the sink catalog.
 * Off unless FULLSHIELD_EXPERIMENTAL_RASPV2=1.
 * Reads catalog JSON. Does not import the scanner.
 */
import { readFileSync } from 'node:fs';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_RASPV2';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface CatalogSink {
  package: string;
  member: string;
  argumentIndex: number;
  class: string;
  runtimeGap?: boolean;
}

export interface InstalledHook {
  package: string;
  member: string;
  argumentIndex: number;
  class: string;
}

const KNOWN_CLASSES = new Set(['sql', 'shell', 'path', 'ssrf', 'nosql', 'proto', 'deser', 'ssti', 'upload', 'ws', 'eval']);

export function loadCatalog(path: string): CatalogSink[] {
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  if (!Array.isArray(parsed)) {
    return [];
  }
  return parsed as CatalogSink[];
}

export function installCatalog(rows: readonly CatalogSink[]): { installed: InstalledHook[]; log: string[] } {
  if (!enabled()) {
    return { installed: [], log: [] };
  }
  const installed: InstalledHook[] = [];
  const log: string[] = [];
  const logged = new Set<string>();
  for (const row of rows) {
    if (row.runtimeGap === true) {
      continue;
    }
    if (!KNOWN_CLASSES.has(row.class)) {
      if (!logged.has(row.class)) {
        logged.add(row.class);
        log.push(`unknown catalog class ${row.class}`);
      }
      continue;
    }
    installed.push({
      package: row.package,
      member: row.member,
      argumentIndex: row.argumentIndex,
      class: row.class,
    });
  }
  return { installed, log };
}

/** A hook name that is not a catalog row fails consistency. */
export function assertHooksMatchCatalog(hookIds: readonly string[], rows: readonly CatalogSink[]): void {
  const ids = new Set(rows.map((row) => `${row.package}.${row.member}`));
  for (const hookId of hookIds) {
    if (!ids.has(hookId)) {
      throw new TypeError(`hook ${hookId} is not a catalog row`);
    }
  }
}

export function invokeHook(
  installed: readonly InstalledHook[],
  pkg: string,
  member: string,
  args: readonly unknown[],
  mode: 'monitor' | 'block',
): { action: 'allow' | 'monitor' | 'block' } {
  const hook = installed.find((row) => row.package === pkg && row.member === member);
  if (hook === undefined) {
    return { action: 'allow' };
  }
  const argument = args[hook.argumentIndex];
  const suspicious = typeof argument === 'string' && (argument.includes("' OR '") || argument.includes('../') || argument.includes('$where'));
  if (!suspicious) {
    return { action: 'allow' };
  }
  return { action: mode === 'block' ? 'block' : 'monitor' };
}
