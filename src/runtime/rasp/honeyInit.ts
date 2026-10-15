import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { DECOY_ROUTES, registerCanaries, type HoneyCanaries } from './honey.js';

export type { HoneyCanaries };

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
