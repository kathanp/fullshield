import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { runScan } from '../../../../src/core/engine.js';
import { TRPC_FLAG, scanTrpcSources } from '../../../../src/modules/trpc/index.js';

const saved = process.env[TRPC_FLAG];

afterEach(() => {
  if (saved === undefined) {delete process.env[TRPC_FLAG];}
  else {process.env[TRPC_FLAG] = saved;}
});

async function findings(source: string) {
  return scanTrpcSources([{ file: 'app.js', source }]);
}

describe('3.11.0 trpc module', () => {
  it('flags a procedure input that reaches SQL and stays quiet for a checked field', async () => {
    const positive = await findings(`
      publicProcedure.query(({ input }) => { db.query(input); });
    `);
    const negative = await findings(`
      publicProcedure.query(({ input }) => { db.query(Number(input.id)); });
    `);
    expect(positive.map((item) => item.ruleId)).toContain('TRPC-SQL-001');
    expect(positive.map((item) => item.message)).toContain('tRPC procedure input reaches a SQL call.');
    expect(negative).toEqual([]);
  });

  it('flags a procedure input that reaches a shell and stays quiet for a constant', async () => {
    const positive = await findings(`
      procedure.mutation(({ input }) => { exec(input.cmd); });
    `);
    const negative = await findings(`
      procedure.mutation(({ input }) => { exec('echo ok'); });
    `);
    expect(positive.map((item) => item.ruleId)).toContain('TRPC-CMD-001');
    expect(positive.map((item) => item.message)).toContain('tRPC procedure input reaches a shell call.');
    expect(negative).toEqual([]);
  });

  it('flags a procedure input that reaches a path and stays quiet when an allowlist rejects it', async () => {
    const positive = await findings(`
      procedure.query(({ input }) => { fs.readFileSync(input.path); });
    `);
    const negative = await findings(`
      procedure.query(({ input }) => {
        if (!allow.includes(input.path)) return;
        fs.readFileSync(input.path);
      });
    `);
    expect(positive.map((item) => item.ruleId)).toContain('TRPC-PATH-001');
    expect(positive.map((item) => item.message)).toContain('tRPC procedure input reaches a path call.');
    expect(negative).toEqual([]);
  });

  it('flags a procedure input that reaches a URL and stays quiet for a constant URL', async () => {
    const positive = await findings(`
      procedure.mutation((opts) => { fetch(opts.input); });
    `);
    const negative = await findings(`
      procedure.mutation((opts) => { fetch('https://example.com'); });
    `);
    expect(positive.map((item) => item.ruleId)).toContain('TRPC-SSRF-001');
    expect(positive.map((item) => item.message)).toContain('tRPC procedure input reaches a URL call.');
    expect(negative).toEqual([]);
  });

  it('follows a copied input, a template, and a parse, and stays quiet for parseInt', async () => {
    const copied = await findings(`
      procedure.query(({ input }) => {
        let sql;
        sql = input;
        db.execute(sql);
      });
    `);
    const unpacked = await findings(`
      procedure.query(({ input }) => {
        const { sql } = input;
        db.query(sql);
      });
    `);
    const template = await findings(`
      procedure.query(({ input }) => { db.query(\`SELECT \${input}\`); });
    `);
    const parsed = await findings(`
      procedure.query(({ input }) => { db.query(parse(input)); });
    `);
    const joined = await findings(`
      procedure.query(({ input }) => { db.query(input + ''); });
    `);
    const client = await findings(`
      procedure.mutation((opts) => { axios.get(opts.input); });
    `);
    const cleared = await findings(`
      procedure.query(({ input }) => { db.query(parseInt(input, 10)); });
    `);
    const ignored = await findings(`
      procedure.query(input);
      procedure.query((...rest) => { db.query(rest); });
    `);
    expect(copied.map((item) => item.ruleId)).toContain('TRPC-SQL-001');
    expect(unpacked.map((item) => item.ruleId)).toContain('TRPC-SQL-001');
    expect(template.map((item) => item.ruleId)).toContain('TRPC-SQL-001');
    expect(parsed.map((item) => item.ruleId)).toContain('TRPC-SQL-001');
    expect(joined.map((item) => item.ruleId)).toContain('TRPC-SQL-001');
    expect(client.map((item) => item.ruleId)).toContain('TRPC-SSRF-001');
    expect(cleared).toEqual([]);
    expect(ignored).toEqual([]);
  });

  it('does not treat a file that only contains publicProcedure and query as this module', async () => {
    const found = await findings(`
      const publicProcedure = 'publicProcedure';
      const query = 'query';
    `);
    const broken = await findings('function (');
    expect(found).toEqual([]);
    expect(broken).toEqual([]);
  });

  it('stays off the default scan and stays quiet on clean-app with the flag on', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fs-trpc-app-'));
    await writeFile(join(dir, 'app.js'), `publicProcedure.query(({ input }) => { db.query(input); });\n`, 'utf8');
    await writeFile(join(dir, 'package.json'), '{"name":"a","version":"1.0.0"}\n', 'utf8');
    delete process.env[TRPC_FLAG];
    const off = await runScan({ cwd: dir, offline: true });
    expect(off.metadata.modulesRequested).toEqual(['deps', 'secrets', 'sast', 'config']);
    expect(off.findings.some((item) => item.ruleId.startsWith('TRPC-'))).toBe(false);
    process.env[TRPC_FLAG] = '1';
    const on = await runScan({ cwd: dir, modules: ['trpc'], offline: true });
    expect(on.findings.map((item) => item.ruleId)).toContain('TRPC-SQL-001');
    const clean = await runScan({
      cwd: join(import.meta.dirname, '../../../fixtures/clean-app'),
      modules: ['trpc'],
      offline: true,
    });
    expect(clean.findings).toEqual([]);
  });
});
