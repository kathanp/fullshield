import { beforeEach } from 'vitest';

/**
 * Vitest reuses a fork for the next file. `process.env` is the process, so a
 * flag set in one file is still set for the next file when that file's cleanup
 * does not run. Scanner flags change which AST path and which taint rules run,
 * and a leaked parse-pool flag used to drop cross-file findings.
 * Each test starts with no FULLSHIELD_* variables.
 */
beforeEach(() => {
  for (const key of Object.keys(process.env)) {
    if (key.startsWith('FULLSHIELD_')) delete process.env[key];
  }
});
