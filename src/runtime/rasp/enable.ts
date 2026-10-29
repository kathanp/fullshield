import { guardMode, resetWebhookRate, webhookFor } from '../exp/p567.js';
import { matchingSinkLines, responseWithinCap, runtimeMode, sqlFingerprint } from '../exp/p568.js';
import { clearDnsPins, setDnsPinTtl } from './dns-pin.js';
import { decideSink } from './decide.js';
import { installHooks, restoreHooks } from './hooks.js';
import { clearCanaries } from './honey.js';
import { setSsrfLookup } from './ssrf.js';
import { clearThreats, configureThreat } from './threat.js';
import { patchForcesBlock, type VirtualPatch } from './vpatch.js';
import { RASP_RULE, type Decision, type RaspEvent, type RaspRequestContext, type SinkKind } from './types.js';

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
  /** Per-request DNS pin lifetime in ms (default 60 seconds). */
  dnsPinTtlMs?: number;
}

let enabled = false;
let options: RaspOptions = {};
const events: RaspEvent[] = [];
const MAX_EVENTS = 1000;
let pendingWebhook = false;

function noteWebhook(kind: SinkKind, mode: RaspMode): void {
  if (!pendingWebhook) {return;}
  pendingWebhook = false;
  const last = events[events.length - 1];
  if (!last || last.ruleId !== RASP_RULE[kind]) {return;}
  const body = webhookFor(kind, mode, last.ruleId, Date.now());
  if (body !== undefined) {last.webhookJson = body;}
  const fingerprint = kind === 'sql' ? sqlFingerprint(last.sample) : undefined;
  if (fingerprint !== undefined) {last.fingerprint = fingerprint;}
  const lines = matchingSinkLines(last.sample, fingerprint ?? '');
  if (lines.length > 0) {last.sinkLines = lines;}
  if (!responseWithinCap(Buffer.byteLength(last.sample))) {last.overCap = true;}
}

export function isRaspEnabled(): boolean {
  return enabled;
}

export function raspMode(): RaspMode {
  return options.mode ?? 'monitor';
}

export function raspModeFor(route: string, kind: SinkKind): RaspMode {
  const requested = patchForcesBlock(options.virtualPatches ?? [], route, kind) ? 'block' : raspMode();
  const mode = guardMode(requested, kind);
  noteWebhook(kind, mode);
  return mode;
}

export function raspEgressAllow(): readonly string[] | undefined {
  return options.egress?.allow;
}

export function runDecide(kind: SinkKind, sink: unknown, ctx: RaspRequestContext, base?: string): Decision {
  if (options.decide) {return options.decide(kind, sink, ctx);}
  return decideSink(kind, sink, ctx, base);
}

export function emitRaspEvent(event: RaspEvent): void {
  if (events.length >= MAX_EVENTS) {events.shift();}
  events.push(event);
  pendingWebhook = true;
  options.onEvent?.(event);
}

export function getRaspEvents(): readonly RaspEvent[] {
  return events;
}

export function clearRaspEvents(): void {
  events.length = 0;
  pendingWebhook = false;
  resetWebhookRate();
}

export function enableRasp(opts: RaspOptions = {}): void {
  if (!opts.experimental && process.env.FULLSHIELD_EXPERIMENTAL_RASP !== '1') {
    return;
  }
  options = { ...opts, experimental: true };
  setDnsPinTtl(opts.dnsPinTtlMs);
  configureThreat({ autoBlock: opts.threatAutoBlock === true, maxBlockMs: opts.threatMaxBlockMs });
  if (!enabled) {
    installHooks();
    enabled = true;
  }
}

export function disableRasp(): void {
  if (!enabled) {return;}
  restoreHooks();
  enabled = false;
  options = {};
  setSsrfLookup(undefined);
  clearDnsPins();
  setDnsPinTtl(undefined);
  clearCanaries();
  clearThreats();
}

export function enableRaspFromEnv(): void {
  if (process.env.FULLSHIELD_EXPERIMENTAL_RASP !== '1') {return;}
  enableRasp({
    experimental: true,
    mode: runtimeMode(process.env.FULLSHIELD_RASP_MODE),
  });
}
