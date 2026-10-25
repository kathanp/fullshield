import { afterEach, describe, expect, it } from 'vitest';

import { runSastOnText } from '../../../../src/modules/sast/engine.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_SAST_GAPS';
const prisma = `app.get('/u', (req, res) => { prisma.$queryRawUnsafe('SELECT * FROM t WHERE id = ' + req.query.id); });`;

async function has(code: string, ruleId: string): Promise<boolean> {
  return (await runSastOnText('fixture.js', code)).some((finding) => finding.ruleId === ruleId);
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 504 ORM and shell sinks on the default scan', () => {
  it('fires when the flag is 0', async () => {
    process.env[FLAG] = '0';
    await expect(has(prisma, 'SAST-SQLI-001')).resolves.toBe(true);
  });

  it('still ignores a whereRaw bindings array', async () => {
    delete process.env[FLAG];
    await expect(
      has(`app.get('/u', (req, res) => { knex('t').whereRaw('id = ?', [req.query.id]); });`, 'SAST-SQLI-001'),
    ).resolves.toBe(false);
  });
});
