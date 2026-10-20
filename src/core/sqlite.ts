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

const dbHandles = new Set<{ close(): void }>();

/** Remember a database so `fullshield dev` can close it on Ctrl-C. */
export function trackDbHandle(handle: { close(): void }): void {
  dbHandles.add(handle);
}

/** Close every tracked database. A second call is a no-op. */
export function closeAllDbHandles(): void {
  for (const handle of dbHandles) {
    try {
      handle.close();
    } catch {
      // already closed
    }
  }
  dbHandles.clear();
}
