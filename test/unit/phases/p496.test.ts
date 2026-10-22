import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const script = join(root, 'scripts', 'phase496-threatdoc.mjs');
const spec = readFileSync(join(root, 'SECURITY_SCANNER_SPEC.md'), 'utf8');

function run(args: readonly string[], flag: boolean) {
  const env = { ...process.env };
  if (flag) env.FULLSHIELD_EXPERIMENTAL_THREATDOC = '1';
  else delete env.FULLSHIELD_EXPERIMENTAL_THREATDOC;
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf8', env });
}

function openingPhrases(text: string): string[] {
  const start = text.indexOf('## 31. Explicitly Rejected');
  const end = text.indexOf('\n## ', start + 10);
  const section = text.slice(start, end);
  const phrases: string[] = [];
  for (const line of section.split('\n')) {
    const match = /^- \[ X \] (.+)$/.exec(line);
    const body = match?.[1];
    if (body === undefined) continue;
    const dot = body.indexOf('.');
    const colon = body.indexOf(':');
    const cuts = [dot, colon].filter((index) => index >= 0);
    const cut = cuts.length === 0 ? body.length : Math.min(...cuts);
    phrases.push(body.slice(0, cut).trim());
  }
  return phrases;
}

const banned = [
  'number 1',
  'best',
  'leader',
  'one of a kind',
  'complete protection',
  'prevents attacks',
  'full shield from cyber attacks',
];

describe('phase 496 threat model', () => {
  it('includes every Section 31 opening phrase and keeps reviewed false', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs496-'));
    const out = join(dir, 'threat-model.md');
    const result = run(['--out', out], true);
    expect(result.status).toBe(0);
    const doc = readFileSync(out, 'utf8');
    expect(doc).toContain('reviewed: false');
    expect(doc.includes('reviewed: true')).toBe(false);
    for (const phrase of openingPhrases(spec)) expect(doc).toContain(phrase);
    for (const phrase of banned) expect(doc.includes(phrase)).toBe(false);
    expect(doc).toContain('source under scan');
    expect(doc).toContain('is untrusted and is not executed');
    expect(doc).toContain('R15 host list');
  });

  it('fails a threat with no phase link and no not covered', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fs496b-'));
    const file = join(dir, 'threat.md');
    const generated = run(['--out', join(dir, 'base.md')], true);
    expect(generated.status).toBe(0);
    const broken = readFileSync(join(dir, 'base.md'), 'utf8').replace(/phase \d+/g, 'unlinked');
    writeFileSync(file, broken);
    const result = run(['--check', file], true);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('no link');
  });

  it('does nothing when the flag is off', () => {
    const result = run([], false);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
  });
});
