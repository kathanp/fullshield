export const DECOY_ROUTES = ['/admin.php', '/.git/config', '/wp-login.php'] as const;

export interface HoneyCanaries {
  awsKey: string;
  dbUrl: string;
}

const registered = new Set<string>();
const ROUTE_WINDOW_MS = 60_000;
const routeHits = new Map<string, { count: number; start: number }>();

export function registerCanaries(values: readonly string[]): void {
  for (const v of values) {registered.add(v);}
}

export function clearCanaries(): void {
  registered.clear();
  routeHits.clear();
}

export function isHoneyRoute(path: string): boolean {
  const p = path.split('?')[0] ?? path;
  return (DECOY_ROUTES as readonly string[]).includes(p);
}

export function isHoneyCanary(text: string): boolean {
  if (!text) {return false;}
  for (const c of registered) {
    if (c && text.includes(c)) {return true;}
  }
  return false;
}

/** Count decoy-route hits per IP in a sliding window (aggregated, low severity). */
export function noteHoneyRouteHit(ip: string, now = Date.now()): number {
  const prev = routeHits.get(ip);
  if (prev === undefined || now - prev.start > ROUTE_WINDOW_MS) {
    routeHits.set(ip, { count: 1, start: now });
    return 1;
  }
  prev.count += 1;
  return prev.count;
}
