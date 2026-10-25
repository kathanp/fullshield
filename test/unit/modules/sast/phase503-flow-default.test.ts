import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const field = 'function go(req) {\n  const obj = {};\n  obj.a = req.body.id;\n  db.query(obj.a);\n}\n';

afterEach(() => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_FLOW2;
});

describe('phase 503 field and closure taint on the default scan', () => {
  it('fires when the flag is unset and when it is 0', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_FLOW2;
    const unset = await runSastOnText('fixture.js', field);
    expect(unset.some((finding) => finding.ruleId === 'SAST-SQLI-001')).toBe(true);
    process.env.FULLSHIELD_EXPERIMENTAL_FLOW2 = '0';
    const zero = await runSastOnText('fixture.js', field);
    expect(zero.some((finding) => finding.ruleId === 'SAST-SQLI-001')).toBe(true);
  });

  it('keeps clean-app at zero findings with the flag unset', async () => {
    delete process.env.FULLSHIELD_EXPERIMENTAL_FLOW2;
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });
});
