import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase481-unsoundreg.mjs');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_UNSOUNDREG = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_UNSOUNDREG;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

const opening = 'exhaustion over-approximates in sound mode and does not drop facts silently';

function doc(headings: string, reason: string) {
  return `---\nreviewed: false\n---\n\n${opening}\n\n${headings}\n${reason}\n`;
}

describe('phase 481 unsoundness register', () => {
  it('accepts a heading for every current kind and keeps the opening sentence', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs481-'));
    const enumPath = join(dir, 'unsound.ts');
    const docPath = join(dir, 'unsoundness.md');
    writeFileSync(enumPath, "export const UNSOUND_KINDS = ['dynamic-property'] as const;\n");
    const reason = 'Human reason: the callee set is unknown.';
    writeFileSync(docPath, doc('## dynamic-property', reason));
    const result = run(['--enum', enumPath, '--doc', docPath], true);
    expect(result.status).toBe(0);
    expect(readFileSync(docPath, 'utf8')).toContain(reason);
    expect(readFileSync(docPath, 'utf8')).toContain(opening);
  });

  it('fails a scratch kind without a heading and does not rewrite the reason', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs481b-'));
    const enumPath = join(dir, 'unsound.ts');
    const docPath = join(dir, 'unsoundness.md');
    writeFileSync(enumPath, "export const UNSOUND_KINDS = ['dynamic-property', 'scratch-kind'] as const;\n");
    const reason = 'Human reason stays.';
    writeFileSync(docPath, doc('## dynamic-property', reason));
    const before = readFileSync(docPath, 'utf8');
    const result = run(['--enum', enumPath, '--doc', docPath], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('scratch-kind');
    expect(readFileSync(docPath, 'utf8')).toBe(before);
  });

  it('fails an empty reason line and does not write one', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs481c-'));
    const enumPath = join(dir, 'unsound.ts');
    const docPath = join(dir, 'unsoundness.md');
    writeFileSync(enumPath, "export const UNSOUND_KINDS = ['dynamic-property'] as const;\n");
    writeFileSync(docPath, doc('## dynamic-property', ''));
    const before = readFileSync(docPath, 'utf8');
    const result = run(['--enum', enumPath, '--doc', docPath], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('reason absent (human-owned): dynamic-property');
    expect(readFileSync(docPath, 'utf8')).toBe(before);
  });

  it('checks the repo enum and doc without rewriting the reason', () => {
    const docPath = join(root, 'docs', 'unsoundness.md');
    const before = readFileSync(docPath);
    const result = run(['--repo'], true);
    expect(readFileSync(docPath).equals(before)).toBe(true);
    const text = `${result.stdout}${result.stderr}`;
    expect(text.includes('reason absent (human-owned)') || text.includes('unsoundness headings match')).toBe(true);
    expect(text.toLowerCase().includes('the engine is sound')).toBe(false);
  });

  it('parks when no enum is supplied and does nothing with the flag off', () => {
    const parked = run([], true);
    expect(parked.status).not.toBe(0);
    expect(parked.stderr).toContain('parked (S3)');
    const off = run([], false);
    expect(off.status).toBe(0);
    expect(off.stdout).toBe('');
  });
});
