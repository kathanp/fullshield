import { describe, expect, it } from 'vitest';

import { diffEnv, ENV_MISSING, ENV_UNREAD, FLAG } from '../../../src/phases/p462.js';

const token = `AKIA${'Z'.repeat(16)}`;

describe('phase 462', () => {
  it('reports a read with no example key and an unread example key', () => {
    process.env[FLAG] = '1';
    const result = diffEnv(
      [{ path: 'src/db.js', text: 'const value = process.env.DATABASE_URL;\n' }],
      'UNUSED_KEY=\n',
    );
    expect(result.findings.some((row) => row.ruleId === ENV_MISSING && row.message.includes('DATABASE_URL'))).toBe(true);
    expect(result.findings.some((row) => row.ruleId === ENV_UNREAD && row.message.includes('no read in the scan set'))).toBe(true);
  });

  it('ignores a token that exists only in .env and does not invent a computed name', () => {
    process.env[FLAG] = '1';
    const result = diffEnv(
      [
        { path: '.env', text: `TOKEN=${token}\n` },
        { path: 'src/app.js', text: 'const value = process.env[name];\n' },
      ],
      '',
    );
    expect(JSON.stringify(result)).not.toContain(token);
    expect(result.events.some((event) => event.reason.includes('computed'))).toBe(true);
    expect(result.findings.some((row) => row.message.includes('name'))).toBe(false);
  });

  it('returns the baseline when the flag is off', () => {
    const baseline = [{ ruleId: 'kept', severity: 'info' as const, file: 'a.js', line: 1, message: 'kept' }];
    expect(diffEnv([{ path: 'src/a.js', text: 'process.env.DATABASE_URL' }], '', [], baseline).findings).toEqual(baseline);
  });
});
