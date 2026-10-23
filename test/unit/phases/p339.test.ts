import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p339.js';
import type { SecretFormat } from '../../../src/phases/p332.js';

const TOKEN = 'fsyn_ABCDEFGHIJKLMNOP';
const formats: SecretFormat[] = [{
  id: 'synth', source: 'https://example.invalid/grammar', prefix: 'fsyn_', alphabet: 'A-Za-z0-9', length: 16, notBeforeLength: 21,
  synthetic: [{ value: TOKEN, synthetic: true }],
}];


afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 339', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.sourceMapFindings('a.js', 'sourceMappingURL=https://example.invalid/a.map', []).fetched).toBe(false);
    expect(phase.sourceMapFindings('a.js', 'sourceMappingURL=https://example.invalid/a.map', []).findings).toEqual([]);
  });

  it('reports a remote map without fetching it and ignores a local json map', () => {
    process.env[phase.FLAG] = '1';
    const remote = phase.sourceMapFindings('app.js', '//# sourceMappingURL=https://example.invalid/a.map', []);
    expect(remote.fetched).toBe(false);
    expect(remote.findings[0]?.ruleId).toBe('SECRETS-SRCMAP-001');
    const local = phase.sourceMapFindings('app.js', JSON.stringify({ sources: ['src/a.js'], sourcesContent: ['const a = 1'] }), []);
    expect(local.findings).toEqual([]);
    expect(local.fetched).toBe(false);
  });

  it('reports an absolute path and a secret in sourcesContent', () => {
    process.env[phase.FLAG] = '1';
    const remote = phase.sourceMapFindings('app.js', '//# sourceMappingURL=http://example.invalid/a.map', formats);
    expect(remote.findings[0]?.message).toContain('not fetched');
    expect(phase.sourceMapFindings('app.js', 'sourceMappingURL=file:///tmp/a.map', formats).findings).toEqual([]);
    expect(phase.sourceMapFindings('app.js', '{', formats).events[0]?.detail).toBe('source map parse failed');
    expect(phase.sourceMapFindings('app.js', '1', formats).events[0]?.detail).toBe('source map parse failed');
    expect(phase.sourceMapFindings('app.js', 'null', formats).events[0]?.detail).toBe('source map parse failed');
    expect(phase.sourceMapFindings('app.js', '[]', formats).findings).toEqual([]);
    expect(phase.sourceMapFindings('app.js', '{"sources":"/tmp/a.js"}', formats).findings).toEqual([]);
    const huge = phase.sourceMapFindings('app.js', 'x'.repeat(20), formats, 4);
    expect(huge.events[0]?.detail).toBe('source map fuel exhausted');
    const mapped = phase.sourceMapFindings('app.js', JSON.stringify({
      sources: ['/tmp/a.js', 'test/fixtures/secret.js', 'src/a.js'],
      sourcesContent: [TOKEN, TOKEN, 'const a = 1', 1],
    }), formats);
    expect(mapped.findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining(['SECRETS-SRCMAP-001', 'SECRETS-FORMAT-001']));
    expect(mapped.findings.some((finding) => finding.file === 'src/a.js')).toBe(false);
    expect(phase.sourceMapFindings('test/fixtures/app.js', JSON.stringify({ sourcesContent: [TOKEN] }), formats).findings).toEqual([]);
    expect(phase.sourceMapFindings('pkg\\test\\fixtures\\app.js', JSON.stringify({ sourcesContent: [TOKEN] }), formats).findings).toEqual([]);
  });
});
