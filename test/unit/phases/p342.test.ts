import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p342.js';
import type { SecretFormat } from '../../../src/phases/p332.js';

const TOKEN = 'fsyn_ABCDEFGHIJKLMNOP';
const formats: SecretFormat[] = [{
  id: 'synth', source: 'https://example.invalid/grammar', prefix: 'fsyn_', alphabet: 'A-Za-z0-9', length: 16, notBeforeLength: 21,
  synthetic: [{ value: TOKEN, synthetic: true }],
}];


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 342', () => {
  it('exits 0 without scanning when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    const result = phase.scanStaged({ diff: '+sk_abcdefgh', formats: [], failOn: true, timer: { elapsedMs: () => 0 } });
    expect(result.exitCode).toBe(0);
    expect(result.executedProject).toBe(false);
  });

  it('keeps removed lines out of the added set and stops on a budget', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.addedLines('+++ b/a.js\n-secret\n+plain\n').map((row) => row.line)).toEqual(['plain']);
    const stopped = phase.scanStaged({
      diff: '+++ b/a.js\n+one\n+++ b/b.js\n+two',
      formats: [],
      failOn: true,
      timer: { elapsedMs: () => 50 },
      budgetMs: 10,
    });
    expect(stopped.exitCode).toBe(0);
    expect(stopped.output).toContain('budget stopped');
    expect(stopped.executedProject).toBe(false);
  });

  it('fails only when a staged secret is found and failOn is set', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.addedLines(`+${TOKEN}\n+++ b/a.js\n+plain`).map((row) => row.file)).toEqual(['', 'a.js']);
    const hit = phase.scanStaged({ diff: `+++ b/a.js\n+${TOKEN}\n+more`, formats, failOn: true, timer: { elapsedMs: () => 0 } });
    expect(hit.exitCode).toBe(1);
    expect(hit.output).not.toContain('budget');
    const kept = phase.scanStaged({ diff: `+++ b/a.js\n+${TOKEN}`, formats, failOn: false, timer: { elapsedMs: () => 0 }, budgetMs: 1000 });
    expect(kept.exitCode).toBe(0);
    expect(kept.executedProject).toBe(false);
  });
});
