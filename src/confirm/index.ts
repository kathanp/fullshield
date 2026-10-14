const DESTRUCTIVE =
  /\b(drop|delete|update|insert|truncate|alter)\b|\brm\s|unlink|mkfs|\bdd\s|format\s|>\s*\/dev/i;

export interface ConfirmContainer {
  id: string;
  host: string;
  ip: string;
}

const containers = new Map<string, ConfirmContainer>();

export function registerConfirmContainer(entry: ConfirmContainer): void {
  containers.set(entry.id, entry);
}

export function resetConfirmContainers(): void {
  containers.clear();
}

function hostnameOf(raw: string): { host: string; href: string; rawHost: string } {
  const href = raw.includes('://') ? raw : `http://${raw}`;
  const url = new URL(href);
  const m = href.match(/^https?:\/\/([^/?#]+)/i);
  let authority = m?.[1] ?? url.hostname;
  if (authority.includes('@')) authority = authority.slice(authority.lastIndexOf('@') + 1);
  let rawHost: string;
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']');
    rawHost = end >= 0 ? authority.slice(0, end + 1) : authority;
  } else {
    rawHost = authority.split(':')[0] ?? url.hostname;
  }
  return { host: url.hostname, href: url.href, rawHost };
}

function isLiteralLocal(host: string): boolean {
  return host === 'localhost' || host === '127.0.0.1';
}

function isRegisteredContainer(host: string): boolean {
  for (const c of containers.values()) {
    if (c.host === host || c.ip === host) return true;
  }
  return false;
}

export interface AssertLocalOptions {
  lookup?: (host: string) => string[];
}

/** Scope lock: localhost, 127.0.0.1, or a container FullShield started. */
export function assertLocalTarget(raw: string, opts: AssertLocalOptions = {}): void {
  let host: string;
  let rawHost: string;
  try {
    const parsed = hostnameOf(raw);
    host = parsed.host;
    rawHost = parsed.rawHost;
  } catch {
    throw new Error(`confirm: refused target ${raw}`);
  }
  if (isLiteralLocal(rawHost) && isLiteralLocal(host)) return;
  if (isRegisteredContainer(host) || isRegisteredContainer(rawHost)) return;
  if (opts.lookup) {
    const ips = opts.lookup(host);
    throw new Error(`confirm: refused target ${raw} (resolved ${ips.join(',')})`);
  }
  throw new Error(`confirm: refused target ${raw} (host ${host} is not localhost/127.0.0.1/FullShield container)`);
}

export function buildCanary(kind: 'sql' | 'shell' | 'path' | 'idor', token: string): string {
  if (DESTRUCTIVE.test(token)) {
    throw new Error('confirm: canary must be harmless (no DROP/DELETE/rm/dd)');
  }
  if (kind === 'sql') return `1 UNION SELECT 0,'${token}'`;
  if (kind === 'shell') return `; echo ${token}`;
  if (kind === 'path') return '../canary.txt';
  return token;
}

export type ConfirmKind = 'sql' | 'shell' | 'path' | 'idor';

export interface ConfirmRoute {
  kind: ConfirmKind;
  method: 'GET' | 'POST';
  path: string;
  param?: string;
  asUser?: string;
  expectOwner?: string;
}

export interface ConfirmOptions {
  experimental?: boolean;
  canaryToken?: string;
  users?: { a: string; b: string };
  routes: ConfirmRoute[];
  fetchImpl?: typeof fetch;
}

export interface Confirmation {
  kind: ConfirmKind;
  status: 'confirmed' | 'unconfirmed';
  proof?: string;
  detail?: string;
}

function curlProof(method: string, url: string, extra = ''): string {
  return `curl -sS -X ${method} ${extra}${url}`.trim();
}

async function probe(
  fetchImpl: typeof fetch,
  url: string,
  method: 'GET' | 'POST',
  body?: unknown,
  headers?: Record<string, string>,
): Promise<{ ok: boolean; text: string }> {
  try {
    const res = await fetchImpl(url, {
      method,
      headers: {
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    return { ok: res.ok, text };
  } catch (err) {
    return { ok: false, text: err instanceof Error ? err.message : String(err) };
  }
}

export async function confirmTarget(
  baseUrl: string,
  opts: ConfirmOptions,
): Promise<{ confirmations: Confirmation[]; skipped?: boolean }> {
  if (!opts.experimental && process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM !== '1') {
    return { confirmations: [], skipped: true };
  }
  try {
    assertLocalTarget(baseUrl);
  } catch (err) {
    return {
      confirmations: [
        {
          kind: 'sql',
          status: 'unconfirmed',
          detail: err instanceof Error ? err.message : String(err),
        },
      ],
    };
  }
  const token = opts.canaryToken ?? `FULLSHIELD_CANARY_${Date.now().toString(16)}`;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const origin = baseUrl.replace(/\/$/, '');
  const confirmations: Confirmation[] = [];
  for (const route of opts.routes) {
    try {
      if (route.kind === 'idor') {
        const url = `${origin}${route.path}`;
        const hit = await probe(fetchImpl, url, route.method, undefined, {
          'x-user': route.asUser ?? opts.users?.b ?? 'bob',
        });
        const owner = route.expectOwner ?? opts.users?.a ?? 'alice';
        const confirmed = hit.ok && hit.text.includes(owner);
        confirmations.push({
          kind: 'idor',
          status: confirmed ? 'confirmed' : 'unconfirmed',
          proof: curlProof(route.method, url, `-H 'x-user: ${route.asUser ?? 'bob'}' `),
          detail: hit.text.slice(0, 200),
        });
        continue;
      }
      const payload = buildCanary(route.kind, token);
      const param = route.param ?? 'q';
      let url = `${origin}${route.path}`;
      let body: unknown;
      if (route.method === 'GET') {
        url += `?${encodeURIComponent(param)}=${encodeURIComponent(payload)}`;
      } else {
        body = { [param]: payload };
      }
      const hit = await probe(fetchImpl, url, route.method, body);
      const confirmed =
        hit.text.includes(token) || (route.kind === 'path' && hit.text.includes('FULLSHIELD_CANARY'));
      confirmations.push({
        kind: route.kind,
        status: confirmed ? 'confirmed' : 'unconfirmed',
        proof: curlProof(route.method, url),
        detail: hit.text.slice(0, 200),
      });
    } catch (err) {
      confirmations.push({
        kind: route.kind,
        status: 'unconfirmed',
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return { confirmations };
}
