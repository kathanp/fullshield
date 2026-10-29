/**
 * Phase 567. Monitor-first block allowlist and a local webhook body.
 * Off unless FULLSHIELD_EXPERIMENTAL_RUNTIME_GUARD=1.
 * The body is not posted.
 */
const FLAG = 'FULLSHIELD_EXPERIMENTAL_RUNTIME_GUARD';
const WINDOW_MS = 60_000;
const MAX_BODIES = 5;
const BLOCK_SINKS = new Set(['sql', 'shell']);

export type GuardMode = 'monitor' | 'block';

let stamps: number[] = [];

function on(): boolean {
  return process.env[FLAG] === '1';
}

export function guardMode(requested: GuardMode, kind: string): GuardMode {
  if (!on()) {return requested;}
  if (requested !== 'block') {return 'monitor';}
  if (BLOCK_SINKS.has(kind)) {return 'block';}
  return 'monitor';
}

export function resetWebhookRate(): void {
  stamps = [];
}

export function webhookFor(kind: string, action: GuardMode, ruleId: string, now: number): string | undefined {
  if (!on()) {return undefined;}
  stamps = stamps.filter((t) => now - t < WINDOW_MS);
  if (stamps.length >= MAX_BODIES) {return undefined;}
  stamps.push(now);
  return JSON.stringify({ schema: 1, kind, action, ruleId });
}
