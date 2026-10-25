import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';
import { ldapFindings, ldapOnFiles } from '../../../../src/modules/sast/ldap.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_LDAP';
const ldap = `const ldap = require('ldapjs');\n`;

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 505 LDAP injection', () => {
  it('registers scan --experimental-ldap', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-ldap');
  });

  it('fires when the filter or the DN is request data', async () => {
    process.env[FLAG] = '1';
    const hits = await runSastOnText('fixture.js', `${ldap}function go(req) { ldap.search(req.query.dn, '(uid=a)'); }\n`);
    const ldapHits = hits.filter((finding) => finding.ruleId === 'SAST-LDAP-001');
    expect(ldapHits).toHaveLength(1);
    expect(ldapHits[0]?.severity).toBe('high');
    expect(ldapHits[0]?.line).toBe(2);
    expect(await ids(`${ldap}function go(req) { const f = req.body.filter; ldap.compare('dc=x', 'cn', f); }\n`)).toContain('SAST-LDAP-001');
    expect(await ids(`${ldap}function go(req) { ldap.modify(req.params.dn, []); }\n`)).toContain('SAST-LDAP-001');
    expect(await ids(`${ldap}function go(req) { ldap.bind(req.headers.dn, 'pw'); }\n`)).toContain('SAST-LDAP-001');
    expect(await ids(`${ldap}function go(req) { ldap.search('dc=x', { filter: req.query.f }); }\n`)).toContain('SAST-LDAP-001');
  });

  it('accepts an ldap receiver, a base DN, and skips a file it cannot read', async () => {
    process.env[FLAG] = '1';
    expect(await ids(`function go(req) { ldap.search(req.query.dn, '(uid=a)'); }\n`)).toContain('SAST-LDAP-001');
    expect(await ids(`${ldap}function go(req) { ldap.search('dc=x', { baseDN: req.query.dn }); }\n`)).toContain('SAST-LDAP-001');
    expect(await ids(`${ldap}function go(req) { ldap.search('dc=x', { scope: req.query.f }); }\n`)).not.toContain('SAST-LDAP-001');
    expect(await ids(`${ldap}function go(req) { ldap.search(...req.query.parts); }\n`)).not.toContain('SAST-LDAP-001');
    expect(await ldapFindings('fixture.js', 'ldap {{{')).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-ldap-'));
    expect(await ldapOnFiles(cwd, ['missing.js', 'note.txt'])).toEqual([]);
    await rm(cwd, { recursive: true, force: true });
  });

  it('stays silent for a string-literal filter and for a non-ldap bind', async () => {
    process.env[FLAG] = '1';
    expect(await ids(`${ldap}function go(req) { ldap.search('dc=example', '(uid=alice)'); }\n`)).not.toContain('SAST-LDAP-001');
    expect(await ids(`function go(req) { fn.bind(req.body.id); }\n`)).not.toContain('SAST-LDAP-001');
  });

  it('stays off the default scan', async () => {
    delete process.env[FLAG];
    expect(await ids(`${ldap}function go(req) { ldap.search(req.query.dn, '(uid=a)'); }\n`)).not.toContain('SAST-LDAP-001');
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    process.env[FLAG] = '1';
    const code = `${ldap}function go(req) { ldap.search(req.query.dn, '(uid=a)'); }\n`;
    const key = async () => {
      const findings = await runSastOnText('fixture.js', code);
      return JSON.stringify(findings.map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity]).sort());
    };
    expect(await key()).toBe(await key());
  });
});
