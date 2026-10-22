import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

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
});
