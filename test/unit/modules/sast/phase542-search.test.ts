import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';
import { searchFindings, searchOnFiles } from '../../../../src/modules/sast/search.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_SEARCH';
const elastic = "const { Client } = require('@elastic/elasticsearch');\n";

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

afterEach(() => {
  delete process.env[FLAG];
});

describe('phase 542 search query injection', () => {
  it('registers scan --experimental-search', () => {
    const program = createProgram();
    const scanCommand = program.commands.find((command) => command.name() === 'scan');
    expect(scanCommand!.options.map((option) => option.long)).toContain('--experimental-search');
  });

  it('fires when q or query.query_string.query is request data', async () => {
    process.env[FLAG] = '1';
    const hits = await runSastOnText('fixture.js', `${elastic}function go(req) { client.search({ q: req.query.q }); }\n`);
    const search = hits.filter((finding) => finding.ruleId === 'SAST-SEARCH-001');
    expect(search).toHaveLength(1);
    expect(search[0]?.severity).toBe('high');
    expect(search[0]?.cwe).toBe('CWE-943');
    const nested = `${elastic}function go(req) { client.search({ query: { query_string: { query: req.body.q } } }); }\n`;
    expect(await ids(nested)).toContain('SAST-SEARCH-001');
  });

  it('stays silent for a literal query, ping, and a missing import', async () => {
    process.env[FLAG] = '1';
    expect(await ids(`${elastic}function go(req) { client.search({ q: 'x' }); }\n`)).not.toContain('SAST-SEARCH-001');
    expect(await ids(`${elastic}function go(req) { client.ping(); }\n`)).not.toContain('SAST-SEARCH-001');
    expect(await ids(`${elastic}function go(req) { client.index({ body: req.body }); }\n`)).not.toContain('SAST-SEARCH-001');
    expect(await ids('function go(req) { client.search({ q: req.query.q }); }\n')).not.toContain('SAST-SEARCH-001');
  });

  it('stays off the default scan and skips a file it cannot read', async () => {
    delete process.env[FLAG];
    expect(await ids(`${elastic}function go(req) { client.search({ q: req.query.q }); }\n`)).not.toContain('SAST-SEARCH-001');
    process.env[FLAG] = '1';
    expect(await searchFindings('fixture.js', `${elastic}function go(req) { {{{`)).toEqual([]);
    const cwd = await mkdtemp(join(tmpdir(), 'fullshield-search-'));
    expect(await searchOnFiles(cwd, ['missing.js', 'note.txt'])).toEqual([]);
    await rm(cwd, { recursive: true, force: true });
  });

  it('keeps clean-app at zero findings with the flag on', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    process.env[FLAG] = '1';
    const code = `${elastic}function go(req) { client.search({ q: req.query.q }); }\n`;
    const key = async () => {
      const findings = await runSastOnText('fixture.js', code);
      return JSON.stringify(findings.map((finding) => [finding.ruleId, finding.file, finding.line, finding.severity]).sort());
    };
    expect(await key()).toBe(await key());
  });
});
