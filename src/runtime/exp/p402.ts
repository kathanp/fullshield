/**
 * Phase 402. Hook integrity at startup.
 * Off unless FULLSHIELD_EXPERIMENTAL_HOOKTAMPER=1.
 * The hash is local. A mismatch logs and, only when configured, refuses to listen.
 */
import { createHash } from 'node:crypto';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_HOOKTAMPER';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export const INSTALLER_SOURCE = 'function installHooks(){return true}\n';

export function hashSource(source: string): string {
  return createHash('sha256').update(source).digest('hex');
}

export const BUILD_HASH = hashSource(INSTALLER_SOURCE);

export interface IntegrityResult {
  critical: boolean;
  listen: boolean;
  log: string;
}

export function checkIntegrity(source: string, config: { refuseOnMismatch?: boolean } = {}, expected = BUILD_HASH): IntegrityResult {
  if (!enabled()) {
    return { critical: false, listen: true, log: '' };
  }
  if (hashSource(source) === expected) {
    return { critical: false, listen: true, log: '' };
  }
  const log = 'critical: hook installer hash mismatch';
  return { critical: true, listen: config.refuseOnMismatch !== true, log };
}
