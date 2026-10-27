import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';
import { xpathFindings, xpathOnFiles } from '../../../../src/modules/sast/xpath.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_XPATH';
const xpath = "const xpath = require('xpath');\n";

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 541 XPath injection', () => {
  it('registers scan --experimental-xpath', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-xpath');
  });

  it('fires when select or evaluate gets request data', async () => {
    process.env[FLAG] = '1';
    const hits = await runSastOnText('fixture.js', `${xpath}function go(req) { select(req.query.q, doc); }\n`);
    const xp = hits.filter((finding) => finding.ruleId === 'SAST-XPATH-001');
    expect(xp).toHaveLength(1);
    expect(xp[0]?.severity).toBe('high');
    expect(xp[0]?.cwe).toBe('CWE-643');
    expect(await ids(`${xpath}function go(req) { select1(req.body.q, doc); }\n`)).toContain('SAST-XPATH-001');
    expect(await ids(`${xpath}function go(req) { evaluate(req.params.q, doc); }\n`)).toContain('SAST-XPATH-001');
  });

  it('stays silent for a literal expression and a missing import', async () => {
    process.env[FLAG] = '1';
    expect(await ids(`${xpath}function go(req) { select('//a', doc); }\n`)).not.toContain('SAST-XPATH-001');
    expect(await ids('function go(req) { select(req.query.q, doc); }\n')).not.toContain('SAST-XPATH-001');
  });

  it('stays off the default scan and skips a file it cannot read', async () => {
    delete process.env[FLAG];
    expect(await ids(`${xpath}function go(req) { select(req.query.q, doc); }\n`)).not.toContain('SAST-XPATH-001');
    process.env[FLAG] = '1';
    expect(await xpathFindings('fixture.js', `${xpath}function go(req) { {{{`)).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-xpath-'));
    expect(await xpathOnFiles(cwd, ['missing.js', 'note.txt'])).toEqual([]);
    await rm(cwd, { recursive: true, force: true });
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    process.env[FLAG] = '1';
    const code = `${xpath}function go(req) { select(req.query.q, doc); }\n`;
    const key = async () => {
      const findings = await runSastOnText('fixture.js', code);
      return JSON.stringify(findings.map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity]).sort());
    };
    expect(await key()).toBe(await key());
  });
});
