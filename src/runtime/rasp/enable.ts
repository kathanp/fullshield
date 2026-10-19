import { decideSink } from './decide.js';
import { installHooks, restoreHooks } from './hooks.js';
import { clearCanaries } from './honey.js';
import { setDnsPinTtlMs, setSsrfLookup } from './ssrf.js';
import { clearThreats, configureThreat } from './threat.js';
import { patchForcesBlock, type VirtualPatch } from './vpatch.js';
import type { Decision, RaspEvent, RaspRequestContext, SinkKind } from './types.js';

export type RaspMode = 'monitor' | 'block';

export interface RaspOptions {
  experimental?: boolean;
  mode?: RaspMode;
  onEvent?: (event: RaspEvent) => void;
  decide?: (kind: SinkKind, sink: unknown, ctx: RaspRequestContext) => Decision;
  virtualPatches?: VirtualPatch[];
  egress?: { allow: string[] };
  /** Off by default. Shared-IP (NAT/carrier) risk — see README. */
  threatAutoBlock?: boolean;
  /** Max auto-block duration in ms (default 15 minutes). */
  threatMaxBlockMs?: number;
}

let enabled = false;
let options: RaspOptions = {};
const events: RaspEvent[] = [];
const MAX_EVENTS = 1000;

export function isRaspEnabled(): boolean {
  return enabled;
}

export function raspMode(): RaspMode {
  return options.mode ?? 'monitor';
}

export function raspModeFor(route: string, kind: SinkKind): RaspMode {
  if (patchForcesBlock(options.virtualPatches ?? [], route, kind)) return 'block';
  return raspMode();
}

export function raspEgressAllow(): readonly string[] | undefined {
  return options.egress?.allow;
}

export function runDecide(kind: SinkKind, sink: unknown, ctx: RaspRequestContext, base?: string): Decision {
  if (options.decide) return options.decide(kind, sink, ctx);
  return decideSink(kind, sink, ctx, base);
}

export function emitRaspEvent(event: RaspEvent): void {
  if (events.length >= MAX_EVENTS) events.shift();
  events.push(event);
  options.onEvent?.(event);
}

export function getRaspEvents(): readonly RaspEvent[] {
  return events;
}

export function clearRaspEvents(): void {
  events.length = 0;
}

export function enableRasp(opts: RaspOptions = {}): void {
  if (!opts.experimental && process.env.FULLSHIELD_EXPERIMENTAL_RASP !== '1') {
    return;
  }
  options = { ...opts, experimental: true };
  configureThreat({ autoBlock: opts.threatAutoBlock === true, maxBlockMs: opts.threatMaxBlockMs });
  if (!enabled) {
    installHooks();
    enabled = true;
  }
}

export function disableRasp(): void {
  if (!enabled) return;
  restoreHooks();
  enabled = false;
  options = {};
  setSsrfLookup(undefined);
  setDnsPinTtlMs(undefined);
  clearCanaries();
  clearThreats();
}

export function enableRaspFromEnv(): void {
  if (process.env.FULLSHIELD_EXPERIMENTAL_RASP !== '1') return;
  enableRasp({
    experimental: true,
    mode: process.env.FULLSHIELD_RASP_MODE === 'block' ? 'block' : 'monitor',
  });
}
