/**
 * Phase 387. SSRF hook on resolved addresses.
 * Off unless FULLSHIELD_EXPERIMENTAL_SSRF2=1.
 * The resolver is injected. This module does not connect and does not scan a remote host.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SSRF2';
export const METADATA = '169.254.169.254';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export class FsError extends Error {
  readonly code = 'FS-E' as const;
  constructor(message: string) {
    super(message);
    this.name = 'FsError';
  }
}

export function validateSsrfAllow(hosts: readonly string[]): void {
  if (hosts.includes(METADATA) || hosts.includes('169.254.169.254/32')) {
    throw new FsError('metadata address cannot be allowlisted');
  }
}

function decimalIp(host: string): string | null {
  if (!/^\d+$/.test(host)) {
    return null;
  }
  const value = Number(host);
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    return null;
  }
  return `${(value >>> 24) & 255}.${(value >>> 16) & 255}.${(value >>> 8) & 255}.${value & 255}`;
}

function hexIp(host: string): string | null {
  if (!/^0x[0-9a-f]+$/i.test(host)) {
    return null;
  }
  const value = Number(host);
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    return null;
  }
  return `${(value >>> 24) & 255}.${(value >>> 16) & 255}.${(value >>> 8) & 255}.${value & 255}`;
}

export function literalIp(host: string): string | null {
  const dotted = /^(?:\d{1,3}\.){3}\d{1,3}$/.exec(host);
  if (dotted !== null) {
    return host;
  }
  return decimalIp(host) ?? hexIp(host);
}

export interface StaticUrl {
  finding: boolean;
  soundness: boolean;
  message: string;
}

export function staticUrl(raw: string): StaticUrl {
  if (!enabled()) {
    return { finding: false, soundness: false, message: '' };
  }
  let host = '';
  try {
    host = new URL(raw).hostname;
  } catch {
    return { finding: false, soundness: false, message: '' };
  }
  const ip = literalIp(host);
  if (ip !== null) {
    return { finding: true, soundness: false, message: `Literal IP form ${host} resolves to ${ip}.` };
  }
  return { finding: false, soundness: true, message: 'Hostname is not a literal IP. Rebinding is not a static fact.' };
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) {
    return null;
  }
  let value = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      return null;
    }
    value = (value << 8) + octet;
  }
  return value >>> 0;
}

export function blockedAddress(ip: string): boolean {
  if (ip === '::1' || ip === '0:0:0:0:0:0:0:1') {
    return true;
  }
  const value = ipv4ToInt(ip);
  if (value === null) {
    return false;
  }
  const loopback = ipv4ToInt('127.0.0.0');
  const link = ipv4ToInt('169.254.0.0');
  if (loopback === null || link === null) {
    return false;
  }
  return (value & 0xff000000) === (loopback & 0xff000000) || (value & 0xffff0000) === (link & 0xffff0000);
}

export function runtimeAddress(
  host: string,
  resolve: (name: string) => string,
  allow: readonly string[],
  redirects: readonly string[] = [],
  redirectCap = 3,
): { event: boolean } {
  if (!enabled()) {
    return { event: false };
  }
  validateSsrfAllow(allow);
  const names = [host, ...redirects.slice(0, redirectCap)];
  for (const name of names) {
    if (allow.includes(name) && name !== METADATA) {
      continue;
    }
    const ip = literalIp(name) ?? resolve(name);
    if (blockedAddress(ip)) {
      return { event: true };
    }
  }
  return { event: false };
}
