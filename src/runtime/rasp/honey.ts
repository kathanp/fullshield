import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const DECOY_ROUTES = ['/admin.php', '/.git/config', '/wp-login.php'] as const;

export interface HoneyCanaries {
  awsKey: string;
  dbUrl: string;
}

const registered = new Set<string>();
const ROUTE_WINDOW_MS = 60_000;
const routeHits = new Map<string, { count: number; start: number }>();

export function registerCanaries(values: readonly string[]): void {
  for (const v of values) registered.add(v);
}

export function clearCanaries(): void {
  registered.clear();
  routeHits.clear();
}

function ensureGitignore(cwd: string, entries: readonly string[]): void {
  const path = join(cwd, '.gitignore');
  let text = existsSync(path) ? readFileSync(path, 'utf8') : '';
  const have = new Set(text.split('\n').map((l) => l.trim()));
  for (const entry of entries) {
    if (have.has(entry)) continue;
    if (text.length > 0 && !text.endsWith('\n')) text += '\n';
    text += `${entry}\n`;
    have.add(entry);
  }
  writeFileSync(path, text, 'utf8');
}

export function honeyInit(cwd: string): HoneyCanaries {
  // Clearly fake: no AKIA / cloud-key prefix, no user:pass@ URL (secrets + GitHub push protection).
  const awsKey = 'FULLSHIELD-HONEY-CANARY-NOT-A-CLOUD-KEY';
  const dbUrl = 'fullshield-honey-db-canary://local';
  mkdirSync(cwd, { recursive: true });
  writeFileSync(
    join(cwd, '.env.backup'),
    `# fullshield honeytoken decoy — not real credentials\nAWS_ACCESS_KEY_ID=${awsKey}\nDATABASE_URL=${dbUrl}\n`,
    'utf8',
  );
  writeFileSync(
    join(cwd, '.fullshield-honey.json'),
    `${JSON.stringify({ decoys: DECOY_ROUTES, canaries: { awsKey, dbUrl } }, null, 2)}\n`,
    'utf8',
  );
  ensureGitignore(cwd, ['.env.backup', '.fullshield-honey.json']);
  registerCanaries([awsKey, dbUrl]);
  return { awsKey, dbUrl };
}

export function isHoneyRoute(path: string): boolean {
  const p = path.split('?')[0] ?? path;
  return (DECOY_ROUTES as readonly string[]).includes(p);
}

export function isHoneyCanary(text: string): boolean {
  if (!text) return false;
  for (const c of registered) {
    if (c && text.includes(c)) return true;
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
