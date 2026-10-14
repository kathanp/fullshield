function isPrivateOrMetadata(host: string): boolean {
  const h = host.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h === 'metadata.google.internal') return true;
  if (h === '::1' || h === '::' || h === '0.0.0.0') return true;
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(h);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    if (a === 127 || a === 0 || a === 10) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    return false;
  }
  if (h.includes(':')) {
    if (h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80:')) return true;
    if (h.startsWith('::ffff:')) return isPrivateOrMetadata(h.slice(7));
  }
  return false;
}

/** Block when user input overlaps the URL hostname and that host is private/metadata. */
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
  const hostStart = url.indexOf(host);
  if (hostStart === -1) return false;
  const hostEnd = hostStart + host.length;
  let from = 0;
  while (from <= url.length) {
    const idx = url.indexOf(input, from);
    if (idx === -1) break;
    const end = idx + input.length;
    if (idx < hostEnd && end > hostStart && isPrivateOrMetadata(host)) return true;
    from = idx + Math.max(input.length, 1);
  }
  return false;
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
