import dns from 'node:dns';

import { currentRaspContext } from './context.js';

export type HostLookup = (host: string) => string[];

let lookupImpl: HostLookup | undefined;
const PIN_CAP = 1000;
let dnsPinTtlMs = 60_000;

interface DnsPin {
  addresses: string[];
  at: number;
}

const pinsByRequest = new WeakMap<object, Map<string, DnsPin>>();

export function setDnsPinTtlMs(ms: number | undefined): void {
  dnsPinTtlMs = ms === undefined || !Number.isFinite(ms) || ms < 0 ? 60_000 : ms;
}

/**
 * Pin the first resolved set for this host inside the current request.
 * A later set that adds a private, loopback, link-local, or metadata address is refused until the TTL.
 * Resolver trouble and a missing request context fail open.
 */
export function dnsPinBlocks(host: string, addresses: readonly string[], now = Date.now()): boolean {
  try {
    const ctx = currentRaspContext();
    if (!ctx || addresses.length === 0) return false;
    const key = normalizeHost(host);
    let pins = pinsByRequest.get(ctx);
    if (!pins) {
      pins = new Map();
      pinsByRequest.set(ctx, pins);
    }
    const prev = pins.get(key);
    if (prev) pins.delete(key);
    if (!prev || now - prev.at >= dnsPinTtlMs) {
      if (pins.size >= PIN_CAP) {
        const oldest = pins.keys().next().value;
        if (oldest !== undefined) pins.delete(oldest);
      }
      pins.set(key, { addresses: addresses.map((addr) => normalizeHost(addr)), at: now });
      return false;
    }
    pins.set(key, prev);
    const known = new Set(prev.addresses);
    return addresses.some((addr) => {
      const normalized = normalizeHost(addr);
      return !known.has(normalized) && isPrivateOrMetadata(normalized);
    });
  } catch {
    return false;
  }
}

export function setSsrfLookup(fn: HostLookup | undefined): void {
  lookupImpl = fn;
}

export function normalizeHost(host: string): string {
  let h = host.trim().toLowerCase();
  h = h.replace(/\.+$/, '');
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (h.startsWith('::ffff:')) h = h.slice(7);
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  return h;
}

function parseIpv4Part(part: string): number | undefined {
  if (/^0x[0-9a-f]+$/i.test(part)) {
    const n = Number.parseInt(part, 16);
    return Number.isFinite(n) ? n : undefined;
  }
  if (/^0[0-7]+$/.test(part)) {
    const n = Number.parseInt(part, 8);
    return Number.isFinite(n) ? n : undefined;
  }
  if (/^\d+$/.test(part)) {
    const n = Number(part);
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

/** inet_aton-style IPv4 including decimal, octal, hex, and short forms. */
export function parseIpv4(host: string): [number, number, number, number] | undefined {
  const h = normalizeHost(host);
  if (!h || h.includes(':')) return undefined;
  const parts = h.split('.');
  if (parts.length === 0 || parts.length > 4) return undefined;
  const nums = parts.map(parseIpv4Part);
  if (nums.some((n) => n === undefined)) return undefined;
  const a = nums[0]!;
  if (parts.length === 1) {
    if (a > 0xffffffff) return undefined;
    return [(a >>> 24) & 255, (a >>> 16) & 255, (a >>> 8) & 255, a & 255];
  }
  if (parts.length === 2) {
    const b = nums[1]!;
    if (a > 255 || b > 0xffffff) return undefined;
    return [a, (b >>> 16) & 255, (b >>> 8) & 255, b & 255];
  }
  if (parts.length === 3) {
    const b = nums[1]!;
    const c = nums[2]!;
    if (a > 255 || b > 255 || c > 0xffff) return undefined;
    return [a, b, (c >>> 8) & 255, c & 255];
  }
  const b = nums[1]!;
  const c = nums[2]!;
  const d = nums[3]!;
  if ([a, b, c, d].some((n) => n > 255)) return undefined;
  return [a, b, c, d];
}

function isPrivateV4(octets: [number, number, number, number]): boolean {
  const [a, b] = octets;
  if (a === 127 || a === 0 || a === 10) return true;
  if (a === 169 && b === 254) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

function isPrivateIpv6(h: string): boolean {
  if (h === '::1' || h === '::' || h === '0:0:0:0:0:0:0:1') return true;
  if (h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80:')) return true;
  return false;
}

export function isPrivateOrMetadata(host: string): boolean {
  const h = normalizeHost(host);
  if (h === 'localhost' || h.endsWith('.localhost') || h === 'metadata.google.internal') return true;
  const v4 = parseIpv4(h);
  if (v4) return isPrivateV4(v4);
  if (h.includes(':')) return isPrivateIpv6(h);
  return false;
}

function defaultLookup(host: string): string[] {
  const h = normalizeHost(host);
  if (parseIpv4(h) || h.includes(':')) return [h];
  if (lookupImpl) return lookupImpl(h);
  try {
    // Node 22+: dns.lookupSync. If missing, hostname-only checks still apply.
    const lookupSync = (dns as { lookupSync?: (hostname: string, opts: { all: boolean }) => Array<{ address: string }> })
      .lookupSync;
    if (typeof lookupSync === 'function') {
      return lookupSync(h, { all: true }).map((row) => row.address);
    }
  } catch {
    // fail open on resolver errors
  }
  return [];
}

export function resolveHostAddresses(host: string): string[] {
  try {
    return defaultLookup(host);
  } catch {
    return [];
  }
}

export function hostIsBlocked(host: string): boolean {
  if (isPrivateOrMetadata(host)) return true;
  let addresses: string[] = [];
  try {
    addresses = resolveHostAddresses(host);
  } catch {
    return false;
  }
  if (addresses.some((addr) => isPrivateOrMetadata(addr))) return true;
  return dnsPinBlocks(host, addresses);
}

/** Block when user input overlaps the URL hostname and that host (or its resolved IP) is private/metadata. */
export function ssrfHostFromUser(url: string, input: string): boolean {
  if (!input || !url.includes(input)) return false;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  const host = parsed.hostname;
  if (!host) return false;
  const rawAuth = /^https?:\/\/([^/?#]+)/i.exec(url)?.[1] ?? host;
  const rawHost = rawAuth.replace(/:\d+$/, '');
  const inputTouchesHost =
    input === url ||
    input.includes(host) ||
    input.includes(rawHost) ||
    (rawHost.includes(input) && input.length >= 3);
  if (!inputTouchesHost) return false;
  return hostIsBlocked(host) || hostIsBlocked(rawHost);
}

export function urlFromHttpArgs(args: unknown[]): string {
  const first = args[0];
  if (typeof first === 'string') return first;
  if (first instanceof URL) return first.href;
  if (first && typeof first === 'object') {
    const o = first as { href?: string; protocol?: string; hostname?: string; host?: string; path?: string };
    if (typeof o.href === 'string') return o.href;
    const proto = o.protocol ?? 'http:';
    const host = o.hostname ?? o.host ?? '';
    const path = o.path ?? '/';
    return `${proto}//${host}${path}`;
  }
  return '';
}

export function fetchUrl(input: unknown): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  if (input && typeof input === 'object' && 'url' in input && typeof input.url === 'string') {
    return input.url;
  }
  return '';
}
