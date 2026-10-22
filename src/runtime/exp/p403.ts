/**
 * Phase 403. Fail-open counters.
 * Off unless FULLSHIELD_EXPERIMENTAL_FAILOPEN=1.
 * Flag off: a throw fail-opens immediately (previous behavior).
 * Flag on: the hook fail-opens after N throws in the window (default 50).
 * The counter is memory. Nothing is exported from this module onto the network.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_FAILOPEN';
export const DEFAULT_OPEN_AFTER = 50;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface GuardResult {
  blocked: boolean;
  hookRan: boolean;
  log: string;
}

export function createGuardedHook(
  name: string,
  hook: () => 'block' | 'allow',
  threshold = DEFAULT_OPEN_AFTER,
): () => GuardResult {
  let throws = 0;
  let open = false;
  return (): GuardResult => {
    if (open) {
      return { blocked: false, hookRan: false, log: `fail-open tripped ${name}` };
    }
    try {
      const decision = hook();
      return { blocked: decision === 'block', hookRan: true, log: '' };
    } catch {
      throws += 1;
      const limit = enabled() ? threshold : 1;
      if (throws >= limit) {
        open = true;
        return { blocked: false, hookRan: true, log: `fail-open tripped ${name}` };
      }
      return { blocked: false, hookRan: true, log: '' };
    }
  };
}
