import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { INSPECT_RULE } from '../../../src/phases/p463.js';
import { FLAG, scanUnits, UNIT_ROOT, UNIT_SECRET } from '../../../src/phases/p465.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const token = `AKIA${'Z'.repeat(16)}`;

describe('phase 465', () => {
  it('reports User=root, redacts an environment token, and reports inspect', () => {
    process.env[FLAG] = '1';
    const text = `[Service]\nUser=root\nEnvironment=TOKEN=${token}\nExecStart=/usr/bin/node --inspect server.js\n`;
    const findings = scanUnits([{ path: 'docs/deploy/app.service', text }]);
    expect(findings.some((row) => row.ruleId === UNIT_ROOT)).toBe(true);
    expect(findings.some((row) => row.ruleId === UNIT_SECRET)).toBe(true);
    expect(findings.some((row) => row.ruleId === INSPECT_RULE)).toBe(true);
    expect(JSON.stringify(findings)).not.toContain(token);
    expect(findings.map((row) => row.message).join('\n')).toContain('docs/deploy/app.service');
  });

  it('emits nothing for User=node without a secret', () => {
    process.env[FLAG] = '1';
    const findings = scanUnits([{ path: 'app.service', text: '[Service]\nUser=node\nExecStart=/usr/bin/node server.js\n' }]);
    expect(findings).toEqual([]);
  });

  it('returns the baseline when the flag is off and does not import a process API', () => {
    const baseline = [{ ruleId: 'kept', severity: 'high' as const, file: 'app.service', line: 1, message: 'kept' }];
    expect(scanUnits([{ path: 'app.service', text: '[Service]\nUser=root\n' }], baseline)).toEqual(baseline);
    const src = readFileSync(join(root, 'src/phases/p465.ts'), 'utf8');
    expect(src.includes('child_process')).toBe(false);
  });
});
