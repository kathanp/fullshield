import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const register = join(root, 'dist', 'runtime', 'register.js');

const SCRIPT = `
import { DatabaseSync } from 'node:sqlite';
const registerUrl = process.env.FULLSHIELD_REGISTER_URL;
const { enterRaspContext, contextFromRequest } = await import(registerUrl);
const db = new DatabaseSync(':memory:');
db.exec("CREATE TABLE users(id INTEGER, name TEXT); INSERT INTO users VALUES (1, 'admin')");
const payload = "' OR 1=1--";
try {
  enterRaspContext(contextFromRequest({ path: '/q', query: { q: payload } }), () => {
    db.exec("SELECT * FROM users WHERE name = '" + payload + "'");
  });
  console.log('QUERY_RAN');
} catch (err) {
  console.log('QUERY_BLOCKED:' + (err && err.ruleId ? err.ruleId : err));
}
db.close();
`;

describe('RASP --import register (built)', () => {
  it('does not hook sinks without FULLSHIELD_EXPERIMENTAL_RASP', () => {
    const result = spawnSync(process.execPath, ['--import', register, '--input-type=module', '-e', SCRIPT], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_REGISTER_URL: pathToFileURL(register).href },
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('QUERY_RAN');
  });

  it('blocks concatenated SQLi when experimental rasp is enabled in block mode', () => {
    const result = spawnSync(process.execPath, ['--import', register, '--input-type=module', '-e', SCRIPT], {
      cwd: root,
      encoding: 'utf8',
      env: {
        ...process.env,
        FULLSHIELD_REGISTER_URL: pathToFileURL(register).href,
        FULLSHIELD_EXPERIMENTAL_RASP: '1',
        FULLSHIELD_RASP_MODE: 'block',
      },
    });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('QUERY_BLOCKED:RASP-SQL-001');
  });
});
