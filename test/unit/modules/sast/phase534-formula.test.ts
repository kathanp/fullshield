import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { formulaFindings, formulaOnFiles } from '../../../../src/modules/sast/formula.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_FORMULA';

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 534 spreadsheet formula injection', () => {
  it('registers scan --experimental-formula', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-formula');
  });

  it('fires for a csv writer or a .csv writeFile of request data', async () => {
    process.env[FLAG] = '1';
    const hits = await runSastOnText('fixture.js', "const csv = require('csv-stringify');\nfunction go(req) { csv.stringify(req.body); }\n");
    const formula = hits.filter((finding) => finding.ruleId === 'SAST-FORMULA-001');
    expect(formula).toHaveLength(1);
    expect(formula[0]?.severity).toBe('high');
    expect(formula[0]?.cwe).toBe('CWE-1236');
    expect(formula[0]?.line).toBe(2);
    expect(await ids("const csv = require('fast-csv');\nfunction go(req) { csv.write(req.query.row); }\n")).toContain('SAST-FORMULA-001');
    expect(await ids("const csv = require('json2csv');\nfunction go(req) { csv.format(req.params.row); }\n")).toContain('SAST-FORMULA-001');
    expect(await ids("const csv = require('csv');\nfunction go(req) { csv.writeToPath(req.headers.path); }\n")).toContain('SAST-FORMULA-001');
    expect(await ids('function go(req) { fs.writeFile("out.csv", req.body); }\n')).toContain('SAST-FORMULA-001');
    expect(await ids('function go(req) { fs.writeFileSync("out.csv", req.headers.row); }\n')).toContain('SAST-FORMULA-001');
    expect(await ids('function go(req) { fs.writeFile(`out.csv`, req.body); }\n')).toContain('SAST-FORMULA-001');
  });

  it('stays silent for a literal row, a non-csv path, and a writer without the import', async () => {
    process.env[FLAG] = '1';
    expect(await ids("const csv = require('csv-stringify');\nfunction go(req) { csv.stringify('a,b'); }\n")).not.toContain('SAST-FORMULA-001');
    expect(await ids('function go(req) { fs.writeFile("out.txt", req.body); }\n')).not.toContain('SAST-FORMULA-001');
    expect(await ids('function go(req) { fs.writeFile("out.csv", "a,b"); }\n')).not.toContain('SAST-FORMULA-001');
    expect(await ids('function go(req) { fs.write(req.body); }\n')).not.toContain('SAST-FORMULA-001');
    expect(await ids('function go(req) { fs.writeFile(req.query.path, req.body); }\n')).not.toContain('SAST-FORMULA-001');
    expect(await ids('function go(req) { fs.writeFile(...req.query.parts); }\n')).not.toContain('SAST-FORMULA-001');
    expect(await ids('function go(req) { fs.writeFile("out.csv"); }\n')).not.toContain('SAST-FORMULA-001');
  });

  it('stays off the default scan and skips a file it cannot read', async () => {
    delete process.env[FLAG];
    expect(await ids('function go(req) { fs.writeFile("out.csv", req.body); }\n')).not.toContain('SAST-FORMULA-001');
    process.env[FLAG] = '1';
    expect(await formulaFindings('fixture.js', 'function go(req) { {{{')).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-formula-'));
    expect(await formulaOnFiles(cwd, ['missing.js', 'note.txt'])).toEqual([]);
    await rm(cwd, { recursive: true, force: true });
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    process.env[FLAG] = '1';
    const code = 'function go(req) { fs.writeFile("out.csv", req.body); }\n';
    const key = async () => {
      const findings = await runSastOnText('fixture.js', code);
      return JSON.stringify(findings.map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity]).sort());
    };
    expect(await key()).toBe(await key());
  });
});
