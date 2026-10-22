import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  analyzeSoundness,
  buildSoundnessReport,
  enabled,
  FLAG,
  UNSOUND_KINDS,
  writeSoundnessReport,
  type UnsoundKind,
} from '../../../src/phases/p271.js';

const DEPTH = `function c() { return 1; }
function b() { return c(); }
function a() { return b(); }
a();
`;

const FIXPOINT = `function rec(n) { return rec(n); }
`;

const SOUND = `function f(req) {
  const x = mystery(req.query.x);
  db.query(x);
}
`;

describe('phase 271 soundness', () => {
  it('is off unless the flag is 1', () => {
    expect(enabled()).toBe(false);
    process.env[FLAG] = '1';
    expect(enabled()).toBe(true);
  });

  it('records exactly one event per kind', () => {
    process.env[FLAG] = '1';
    const fixtures: { kind: UnsoundKind; source: string; depthCap?: number }[] = [
      { kind: 'dynamic-property', source: 'function f() { const o = {}; const k = name; o[k]; }' },
      { kind: 'eval', source: 'function f() { eval(code); }' },
      { kind: 'unresolved-import', source: "require('./missing.js');" },
      { kind: 'depth-cap', source: DEPTH, depthCap: 1 },
      { kind: 'fixpoint-cap', source: FIXPOINT },
      { kind: 'unknown-callee', source: 'mystery(1);' },
      { kind: 'proxy', source: 'const p = new Proxy({}, {});' },
    ];
    expect(fixtures.map((fixture) => fixture.kind).sort()).toEqual([...UNSOUND_KINDS].sort());
    for (const fixture of fixtures) {
      const result = analyzeSoundness(fixture.source, { file: 'kind.js', depthCap: fixture.depthCap });
      expect(result.events.map((event) => event.kind), fixture.kind).toEqual([fixture.kind]);
      expect(result.events[0]?.file).toBe('kind.js');
    }
  });

  it('adds no findings and no events when the flag is off', () => {
    const result = analyzeSoundness(SOUND, { mode: 'sound' });
    expect(result).toEqual({ events: [], findings: [] });
  });

  it('keeps precise findings byte-identical to the flag-off output', () => {
    const off = analyzeSoundness(SOUND, { mode: 'precise' });
    process.env[FLAG] = '1';
    const precise = analyzeSoundness(SOUND, { mode: 'precise' });
    expect(JSON.stringify(precise.findings)).toBe(JSON.stringify(off.findings));
    expect(precise.findings).toEqual([]);
  });

  it('sound mode is a superset and keeps taint through an unknown callee', () => {
    process.env[FLAG] = '1';
    const precise = analyzeSoundness(SOUND, { mode: 'precise' });
    const sound = analyzeSoundness(SOUND, { mode: 'sound' });
    for (const finding of precise.findings) {
      expect(sound.findings).toContainEqual(finding);
    }
    expect(sound.findings.length).toBeGreaterThan(precise.findings.length);
    expect(sound.findings[0]).toMatchObject({ sinkClass: 'sqli', mode: 'sound' });
    const direct = analyzeSoundness('function f(req) { db.query(req.query.x); }', { mode: 'sound' });
    expect(direct.findings).toEqual([]);
  });

  it('writes a path-only report with the top 50 files and no source text', async () => {
    process.env[FLAG] = '1';
    const source = 'eval("SNIPPET_TOKEN_XYZ")';
    const analysis = analyzeSoundness(source, { file: 'app.js' });
    const dir = await mkdtemp(join(tmpdir(), 'fs-sound-'));
    try {
      const report = writeSoundnessReport(dir, analysis.events);
      const text = readFileSync(join(dir, '.fullshield', 'soundness.json'), 'utf8');
      expect(text).not.toContain('SNIPPET_TOKEN_XYZ');
      expect(text).not.toContain('eval(');
      expect(report.countsByKind.eval).toBe(1);
      expect(report.countsByFile['app.js']).toBe(1);
      const many = [];
      for (let i = 0; i < 60; i += 1) {
        many.push({ kind: 'proxy' as const, file: `f${String(i).padStart(2, '0')}.js`, line: 1, reason: 'Proxy' });
      }
      const top = buildSoundnessReport(many);
      expect(top.topFiles).toHaveLength(50);
      expect(top.topFiles[0]?.file).toBe('f00.js');
      expect(JSON.stringify(top)).not.toContain('SNIPPET_TOKEN_XYZ');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
