import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { localRuleFindings } from '../../../src/modules/sast/parity.js';

const dirs: string[] = [];

afterEach(async () => {
  delete process.env.FULLSHIELD_EXPERIMENTAL_SAST_PARITY;
  for (const dir of dirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'fullshield-stored-'));
  dirs.push(dir);
  return dir;
}

describe('phase 566 stored output on the existing parity flag', () => {
  it('reports a same-file stored response and ignores encoded, framework, and idor shapes', async () => {
    const cwd = await tempDir();
    await mkdir(join(cwd, 'src'), { recursive: true });
    await writeFile(
      join(cwd, 'src', 'stored.js'),
      'const note = req.body.note;\nres.send(note);\n',
      'utf8',
    );
    await writeFile(
      join(cwd, 'src', 'encoded.js'),
      'const note = req.body.note;\nres.send(encodeURIComponent(note));\n',
      'utf8',
    );
    await writeFile(
      join(cwd, 'src', 'frameworks.js'),
      [
        'const rows = await prisma.$queryRaw`SELECT id FROM User WHERE id = ${id}`;',
        'publicProcedure.input(z.object({ id: z.string() }));',
        'create(@Body() dto: CreateUser) {}',
      ].join('\n'),
      'utf8',
    );
    await writeFile(
      join(cwd, 'src', 'idor.js'),
      'app.get("/users/:id", (req, res) => { res.send(User.findById(req.params.id)); });\n',
      'utf8',
    );
    expect(await localRuleFindings(cwd)).toEqual([]);
    process.env.FULLSHIELD_EXPERIMENTAL_SAST_PARITY = '1';
    const hits = await localRuleFindings(cwd);
    expect(hits.map((row) => `${row.file}:${row.line}:${row.severity}`)).toEqual(['src/stored.js:2:medium']);
    expect(hits[0]?.ruleId).toBe('SAST-STORED-001');
    expect(hits[0]?.confidence).toBe('low');
  });
});
