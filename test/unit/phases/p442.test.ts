import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { FOOTER, generateRuleDocs, renderRulePage } from '../../../src/phases/p442.js';

const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function scratch(): { rules: string; out: string } {
  const root = mkdtempSync(join(tmpdir(), 'fs442-'));
  dirs.push(root);
  const rules = join(root, 'rules');
  mkdirSync(rules);
  return { rules, out: join(root, 'out') };
}

describe('phase 442 rule docs', () => {
  it('writes an offline page whose title comes from the markdown id', () => {
    const { rules, out } = scratch();
    writeFileSync(join(rules, 'sql.md'), '---\nid: SAST-SQLI-001\n---\n<script src="https://example.invalid/a.js"></script>\n');
    writeFileSync(join(rules, 'plain.md'), 'no front matter');
    const written = generateRuleDocs(rules, out);
    const pages = new Map(written.map((dest) => [dest, readFileSync(dest, 'utf8')]));
    const sql = pages.get(join(out, 'sql.html')) ?? '';
    const plain = pages.get(join(out, 'plain.html')) ?? '';
    expect(sql).toContain('<h1>SAST-SQLI-001</h1>');
    expect(sql).toContain(FOOTER);
    expect(sql).toContain('&lt;script');
    expect(sql).not.toContain('<script');
    expect(sql).not.toContain('<img');
    expect(sql).not.toContain('<link');
    expect(plain).toContain('<h1>plain</h1>');
    expect(renderRulePage('no front matter', 'plain.md')).toContain('<title>plain</title>');
  });

  it('throws when the rules directory has no markdown file', () => {
    const { rules, out } = scratch();
    writeFileSync(join(rules, 'notes.txt'), 'id: NOPE');
    expect(() => generateRuleDocs(rules, out)).toThrow(`no rule file in ${rules}`);
  });

  it('runs as a script and prints usage when a directory is missing', () => {
    const root = join(fileURLToPath(new URL('.', import.meta.url)), '../../..');
    const script = join(root, 'src/phases/p442.ts');
    const usage = spawnSync(process.execPath, ['--experimental-strip-types', script], { encoding: 'utf8' });
    expect(usage.stderr).toContain('usage: phase442-ruledocs');
    expect(usage.status).not.toBe(0);
    const one = spawnSync(process.execPath, ['--experimental-strip-types', script, root], { encoding: 'utf8' });
    expect(one.stderr).toContain('usage: phase442-ruledocs');
    const { rules, out } = scratch();
    writeFileSync(join(rules, 'sql.md'), 'id: SAST-SQLI-001\nA & B < C > D\n');
    const ran = spawnSync(process.execPath, ['--experimental-strip-types', script, rules, out], { encoding: 'utf8' });
    expect(ran.status).toBe(0);
    expect(readFileSync(join(out, 'sql.html'), 'utf8')).toContain('&amp;');
    const skipped = spawnSync(process.execPath, ['--experimental-strip-types', '--input-type=module', '-e', 'process.argv[1] = undefined; await import("./src/phases/p442.ts");'], {
      cwd: root,
      encoding: 'utf8',
    });
    expect(skipped.status).toBe(0);
  });

  it('takes the direct-run branch inside this process', async () => {
    const previousArgv = process.argv.slice();
    const previousExit = process.exitCode;
    const previousWrite = process.stderr.write.bind(process.stderr);
    const chunks: string[] = [];
    process.stderr.write = ((chunk: string | Uint8Array) => {
      chunks.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;
    try {
      process.argv = ['node', '/tmp/src/phases/p442.ts'];
      process.exitCode = undefined;
      vi.resetModules();
      await import('../../../src/phases/p442.ts');
      expect(chunks.join('')).toContain('usage: phase442-ruledocs');
      expect(process.exitCode).toBe(1);
      const { rules, out } = scratch();
      writeFileSync(join(rules, 'one.md'), 'id: SAST-SQLI-001\n');
      chunks.length = 0;
      process.argv = ['node', '/tmp/src/phases/p442.ts', rules];
      process.exitCode = undefined;
      vi.resetModules();
      await import('../../../src/phases/p442.ts');
      expect(process.exitCode).toBe(1);
      process.argv = ['node', '/tmp/src/phases/p442.ts', rules, out];
      process.exitCode = undefined;
      vi.resetModules();
      await import('../../../src/phases/p442.ts');
      expect(readFileSync(join(out, 'one.html'), 'utf8')).toContain('<h1>SAST-SQLI-001</h1>');
      expect(process.exitCode).toBeUndefined();
    } finally {
      process.argv = previousArgv;
      process.exitCode = previousExit;
      process.stderr.write = previousWrite;
    }
  });
});
