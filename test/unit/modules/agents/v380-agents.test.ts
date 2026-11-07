import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { AGENTS_FLAG, agentsModule, scanAgentsSources } from '../../../../src/modules/agents/index.js';
import { runScan } from '../../../../src/core/engine.js';

const saved = process.env[AGENTS_FLAG];

afterEach(() => {
  if (saved === undefined) {delete process.env[AGENTS_FLAG];}
  else {process.env[AGENTS_FLAG] = saved;}
});

async function ids(files: Array<{ file: string; source: string }>): Promise<string[]> {
  const found = await scanAgentsSources(files);
  return found.map((item) => `${item.ruleId} ${item.file}:${item.line}`);
}

describe('3.8.0 agents module', () => {
  it('flags request data in a system message and stays quiet for a literal and a user role', async () => {
    const system = await ids([{
      file: 'app.js',
      source: 'const msg = { role: "system", content: req.body.q };',
    }]);
    const literal = await ids([{
      file: 'app.js',
      source: 'const msg = { role: "system", content: "You are a helper" };',
    }]);
    const user = await ids([{
      file: 'app.js',
      source: 'const msg = { role: "user", content: req.body.q };',
    }]);
    expect(system.some((item) => item.startsWith('AGENTS-SYSTEM-001'))).toBe(true);
    expect(literal).toEqual([]);
    expect(user).toEqual([]);
  });

  it('flags headers, cookies, and a tool argument', async () => {
    const header = await ids([{
      file: 'app.js',
      source: 'const msg = { role: "system", content: req.headers["x-name"] };',
    }]);
    const cookie = await ids([{
      file: 'app.js',
      source: 'const msg = { role: "system", content: req.cookies.theme };',
    }]);
    const params = await ids([{
      file: 'app.js',
      source: 'const msg = { role: "system", content: req.params.id };',
    }]);
    const tool = await ids([{
      file: 'app.js',
      source: 'const call = { name: "lookup", arguments: req.query.q };',
    }]);
    expect(header.some((item) => item.startsWith('AGENTS-SYSTEM-001'))).toBe(true);
    expect(cookie.some((item) => item.startsWith('AGENTS-SYSTEM-001'))).toBe(true);
    expect(params.some((item) => item.startsWith('AGENTS-SYSTEM-001'))).toBe(true);
    expect(tool.some((item) => item.startsWith('AGENTS-TOOL-001'))).toBe(true);
  });

  it('flags a tool handler that forwards its argument to a shell, a file write, or SQL', async () => {
    const shell = await ids([{
      file: 'app.js',
      source: 'app.tool("run", (args) => { exec(args.cmd); });',
    }]);
    const file = await ids([{
      file: 'app.js',
      source: 'registerTool("save", (args) => { fs.writeFileSync(args.path, "x"); });',
    }]);
    const sql = await ids([{
      file: 'app.js',
      source: 'addTool("q", (args) => { db.query(args.sql); });',
    }]);
    expect(shell.some((item) => item.startsWith('AGENTS-SINK-001'))).toBe(true);
    expect(file.some((item) => item.startsWith('AGENTS-SINK-001'))).toBe(true);
    expect(sql.some((item) => item.startsWith('AGENTS-SINK-001'))).toBe(true);
  });

  it('stays quiet when an allowlist rejects the tool argument', async () => {
    const found = await ids([{
      file: 'app.js',
      source: 'app.tool("run", (args) => { if (!allow.includes(args.cmd)) return; exec(args.cmd); });',
    }]);
    expect(found).toEqual([]);
  });

  it('does not flag a file that only contains the words prompt and system', async () => {
    const found = await ids([{
      file: 'app.js',
      source: 'const label = "prompt";\nconst role = "system";\n',
    }]);
    expect(found).toEqual([]);
  });

  it('follows a helper in another file up to 5 hops and stops at 6', async () => {
    const one = await ids([
      { file: 'app.js', source: 'const { build } = require("./helper");\nbuild(req.body.q);\n' },
      { file: 'helper.js', source: 'function build(text) { return { role: "system", content: text }; }\nmodule.exports = { build };\n' },
    ]);
    expect(one.some((item) => item.startsWith('AGENTS-SYSTEM-001 helper.js'))).toBe(true);

    const chain = (hops: number): Array<{ file: string; source: string }> => {
      const files = [{
        file: 'app.js',
        source: 'const { step1 } = require("./step1");\nstep1(req.query.q);\n',
      }];
      for (let i = 1; i <= hops; i += 1) {
        const body = i === hops
          ? 'return { role: "system", content: text };'
          : `const { step${i + 1} } = require("./step${i + 1}");\nreturn step${i + 1}(text);`;
        files.push({
          file: `step${i}.js`,
          source: `function step${i}(text) { ${body} }\nmodule.exports = { step${i} };\n`,
        });
      }
      return files;
    };
    const five = await ids(chain(5));
    const six = await ids(chain(6));
    expect(five.some((item) => item.startsWith('AGENTS-SYSTEM-001'))).toBe(true);
    expect(six.some((item) => item.startsWith('AGENTS-SYSTEM-001'))).toBe(false);
  });

  it('does not read .cursor, SKILL.md, or a path outside the project', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fs-agents-'));
    await mkdir(join(dir, '.cursor'), { recursive: true });
    const sink = 'const msg = { role: "system", content: req.body.q };\n';
    await writeFile(join(dir, 'app.js'), 'const label = "prompt";\n', 'utf8');
    await writeFile(join(dir, '.cursor', 'secret.js'), sink, 'utf8');
    await writeFile(join(dir, 'SKILL.md'), sink, 'utf8');
    await writeFile(join(tmpdir(), 'fs-agents-outside.js'), sink, 'utf8');
    process.env[AGENTS_FLAG] = '1';
    const found = await agentsModule.run({
      cwd: dir,
      files: ['app.js', '.cursor/secret.js', 'SKILL.md', '../fs-agents-outside.js'],
      config: { modules: ['agents'] } as never,
    });
    expect(found).toEqual([]);
  });

  it('stays off the default scan and stays quiet on clean-app with the flag on', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'fs-agents-app-'));
    await writeFile(join(dir, 'app.js'), 'const msg = { role: "system", content: req.body.q };\n', 'utf8');
    await writeFile(join(dir, 'package.json'), '{"name":"a","version":"1.0.0"}\n', 'utf8');
    delete process.env[AGENTS_FLAG];
    const off = await runScan({ cwd: dir, offline: true });
    expect(off.metadata.modulesRequested).toEqual(['deps', 'secrets', 'sast', 'config']);
    expect(off.findings.some((item) => item.ruleId.startsWith('AGENTS-'))).toBe(false);
    process.env[AGENTS_FLAG] = '1';
    const clean = await runScan({
      cwd: join(import.meta.dirname, '../../../fixtures/clean-app'),
      modules: ['agents'],
      offline: true,
    });
    expect(clean.findings).toEqual([]);
  });
});
