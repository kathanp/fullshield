import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

describe('phase 521 tagged-template SQL and execFile path', () => {
  it('fires SAST-SQLI-001 for a sql tagged template and stays silent without one', async () => {
    const hit = await runSastOnText('db.js', `import { sql } from 'postgres';\nfunction go(req) { sql\`SELECT \${req.query.id}\`; }\n`);
    expect(hit.find((finding) => finding.ruleId === 'SAST-SQLI-001')?.line).toBe(2);
    expect(await ids(`import { sql } from 'postgres';\nfunction go() { sql\`SELECT 1\`; }\n`)).not.toContain('SAST-SQLI-001');
    expect(await ids(`function go(req) { html\`<b>\${req.query.id}</b>\`; }\n`)).not.toContain('SAST-SQLI-001');
    expect(await ids(`import { sql } from 'postgres';\nfunction go(req) { db.query('SELECT $1', [req.query.id]); }\n`)).not.toContain('SAST-SQLI-001');
    expect(await ids(`const db = require('drizzle-orm');\nfunction go(req) { db.sql\`SELECT \${req.body.id}\`; }\n`)).toContain('SAST-SQLI-001');
  });

  it('fires SAST-CMDI-001 when the execFile command path is request data', async () => {
    const hit = await runSastOnText('sh.js', `const { execFile } = require('child_process');\nfunction go(req) { execFile(req.query.bin, ['--ok']); }\n`);
    expect(hit.find((finding) => finding.ruleId === 'SAST-CMDI-001')?.line).toBe(2);
    expect(await ids(`const { execFileSync } = require('child_process');\nfunction go(req) { execFileSync(req.body.bin); }\n`)).toContain('SAST-CMDI-001');
    expect(await ids(`function go(req) { execFile('ping', ['-c', '1', req.body.host]); }\n`)).not.toContain('SAST-CMDI-001');
  });

  it('keeps clean-app at zero findings', async () => {
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    const code = `import { sql } from 'postgres';\nfunction go(req) { sql\`SELECT \${req.query.id}\`; }\n`;
    const key = async () => JSON.stringify((await runSastOnText('db.js', code)).map((finding) => [finding.ruleId, finding.line]));
    expect(await key()).toBe(await key());
  });
});
