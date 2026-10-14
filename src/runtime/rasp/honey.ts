import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const DECOY_ROUTES = ['/admin.php', '/.git/config', '/wp-login.php'] as const;

export interface HoneyCanaries {
  awsKey: string;
  dbUrl: string;
}

const registered = new Set<string>();

export function registerCanaries(values: readonly string[]): void {
  for (const v of values) registered.add(v);
}

export function clearCanaries(): void {
  registered.clear();
}

export function honeyInit(cwd: string): HoneyCanaries {
  const awsKey = `AKIA${'FULLSHIELDDEMO1'}`;
  const dbUrl = 'mongodb://canary:canary@127.0.0.1:27017/honey';
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
