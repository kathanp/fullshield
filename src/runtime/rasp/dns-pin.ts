import { currentRaspContext } from './context.js';

const DEFAULT_TTL_MS = 60_000;
const MAX_HOSTS = 1_000;

interface Pin {
  addresses: Set<string>;
  at: number;
}

const pins = new Map<string, Pin>();
let ttlMs = DEFAULT_TTL_MS;
let nowMs = (): number => Date.now();

export function setDnsPinTtl(ms: number | undefined): void {
  ttlMs = ms !== undefined && Number.isFinite(ms) && ms >= 0 ? ms : DEFAULT_TTL_MS;
}

export function setDnsPinNow(fn: (() => number) | undefined): void {
  nowMs = fn ?? ((): number => Date.now());
}

export function clearDnsPins(): void {
  pins.clear();
}

function touch(key: string, pin: Pin): void {
  pins.delete(key);
  pins.set(key, pin);
  while (pins.size > MAX_HOSTS) {
    const oldest = pins.keys().next().value;
    if (oldest === undefined) {break;}
    pins.delete(oldest);
  }
}

/** True when this request already pinned the host and a new address is private or metadata. */
export function dnsPinBlocks(host: string, addresses: readonly string[], isPrivate: (addr: string) => boolean): boolean {
  const ctx = currentRaspContext();
  if (!ctx || addresses.length === 0) {return false;}
  const key = `${ctx.ip}\0${ctx.path}\0${host}`;
  const now = nowMs();
  const prev = pins.get(key);
  if (!prev || now - prev.at > ttlMs) {
    touch(key, { addresses: new Set(addresses), at: now });
    return false;
  }
  touch(key, prev);
  return addresses.some((addr) => isPrivate(addr) && !prev.addresses.has(addr));
}
