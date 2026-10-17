import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

/** node:sqlite exists on Node >= 22.13. Tests that need it skip otherwise. */
export function hasNodeSqlite(): boolean {
  try {
    require('node:sqlite');
    return true;
  } catch {
    return false;
  }
}
