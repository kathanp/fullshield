import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { scan } from '../../../../src/core/engine.js';
import { runSastOnText } from '../../../../src/modules/sast/index.js';

const cleanApp = join(import.meta.dirname, '../../../fixtures/clean-app');

async function ids(code: string): Promise<string[]> {
  return (await runSastOnText('fixture.js', code)).map((finding) => finding.ruleId);
}

describe('phase 507 sqlite, bun, deno, and library eval', () => {
  it('fires SAST-SQLI-001 for node:sqlite and bun:sqlite exec and prepare', async () => {
    const sqlite = await runSastOnText('db.js', `import { DatabaseSync } from 'node:sqlite';\nfunction go(req) { const db = new DatabaseSync(':memory:'); db.exec('SELECT ' + req.query.id); }\n`);
    const hit = sqlite.find((finding) => finding.ruleId === 'SAST-SQLI-001');
    expect(hit?.severity).toBe('high');
    expect(hit?.line).toBe(2);
    expect(await ids(`const { Database } = require('bun:sqlite');\nfunction go(req) { db.prepare('SELECT ' + req.body.id); }\n`)).toContain('SAST-SQLI-001');
    expect(await ids(`import { DatabaseSync } from 'node:sqlite';\nfunction go(req) { db.prepare('SELECT ?', [req.query.id]); }\n`)).not.toContain('SAST-SQLI-001');
    expect(await ids(`function go(req) { child_process.exec(req.query.id); }\n`)).not.toContain('SAST-SQLI-001');
  });

  it('fires SAST-CMDI-001 for Bun.spawn, Bun.$, and Deno.Command', async () => {
    const bun = await runSastOnText('sh.js', `function go(req) { Bun.spawn(['ls', req.query.path]); }\n`);
    expect(bun.find((finding) => finding.ruleId === 'SAST-CMDI-001')?.line).toBe(1);
    expect(await ids(`function go(req) { Bun.spawn({ cmd: ['ls', req.body.x] }); }\n`)).toContain('SAST-CMDI-001');
    expect(await ids(`function go(req) { Bun.spawnSync(['ls', 'ok']); }\n`)).not.toContain('SAST-CMDI-001');
    expect(await ids('import { $ } from "bun";\nfunction go(req) { $`ls ${req.query.q}`; }\n')).toContain('SAST-CMDI-001');
    expect(await ids('function go(req) { Bun.$`ls ${req.query.q}`; }\n')).toContain('SAST-CMDI-001');
    expect(await ids(`function go(req) { new Deno.Command(req.query.bin, { args: ['--ok'] }); }\n`)).toContain('SAST-CMDI-001');
    expect(await ids(`function go(req) { new Deno.Command('git', { args: [req.params.x] }); }\n`)).toContain('SAST-CMDI-001');
    expect(await ids(`function go(req) { new Deno.Command('git', { args: ['status'] }); }\n`)).not.toContain('SAST-CMDI-001');
  });

  it('fires SAST-EVAL-001 for mathjs, expr-eval, and vm2, and leaves a literal silent', async () => {
    const math = await runSastOnText('ev.js', `import * as mathjs from 'mathjs';\nfunction go(req) { mathjs.evaluate(req.body.expr); }\n`);
    expect(math.find((finding) => finding.ruleId === 'SAST-EVAL-001')?.line).toBe(2);
    expect(await ids(`import { evaluate } from 'mathjs';\nfunction go(req) { evaluate(req.query.q); }\n`)).toContain('SAST-EVAL-001');
    expect(await ids(`const mathjs = require('mathjs');\nfunction go(req) { mathjs.evaluate('1 + 2'); }\n`)).not.toContain('SAST-EVAL-001');
    expect(await ids(`import { Parser } from 'expr-eval';\nfunction go(req) { new Parser().evaluate(req.body.expr); }\n`)).toContain('SAST-EVAL-001');
    expect(await ids(`import { VM } from 'vm2';\nfunction go(req) { new VM({ code: req.body.code }); }\n`)).toContain('SAST-EVAL-001');
    expect(await ids(`import { NodeVM } from 'vm2';\nfunction go(req) { new NodeVM({ code: '1' }); }\n`)).not.toContain('SAST-EVAL-001');
    expect(await ids(`function evaluate(x) { return x; }\nfunction go(req) { evaluate(req.body.expr); }\n`)).not.toContain('SAST-EVAL-001');
  });

  it('keeps clean-app at zero findings', async () => {
    const result = await scan({ cwd: cleanApp, offline: true });
    expect(result.findings).toEqual([]);
  });

  it('is byte-identical across two runs', async () => {
    const code = `import { DatabaseSync } from 'node:sqlite';\nfunction go(req) { db.exec(req.query.id); }\n`;
    const key = async () => JSON.stringify((await runSastOnText('db.js', code)).map((finding) => [finding.ruleId, finding.line]));
    expect(await key()).toBe(await key());
  });
});
