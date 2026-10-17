import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

/** True when this process can load `node:sqlite` (Node >= 22.13). */
export function nodeSqliteAvailable(): boolean {
  try {
    require('node:sqlite');
    return true;
  } catch {
    return false;
  }
}

/**
 * History storage and any confirm path that opens a SQLite database.
 * Scan, fix, and init do not need this module.
 */
export function nodeSqliteUnavailableMessage(feature: string): string {
  return `${feature} requires Node 22.13+ (node:sqlite is not available on Node ${process.versions.node})`;
}
