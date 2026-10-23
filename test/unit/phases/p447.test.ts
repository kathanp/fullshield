import { describe, expect, it } from 'vitest';

import { assertSemverCompatible, emitScanJson, FLAG, SCAN_SCHEMA, STABLE_REQUIRED, validateScanDocument } from '../../../src/phases/p447.js';

const doc = { findings: [], summary: { total: 0 }, metadata: { version: '1.2.0' } };

describe('phase 447', () => {
  it('validates a fixture document', () => {
    expect(validateScanDocument(doc)).toEqual([]);
    expect(SCAN_SCHEMA.required).toEqual([...STABLE_REQUIRED]);
  });

  it('fails the semver check when a required key is deleted', () => {
    expect(() => assertSemverCompatible([...STABLE_REQUIRED], ['summary', 'metadata'])).toThrow(/findings/);
  });

  it('does not add schemaVersion to default JSON', () => {
    const off = emitScanJson(doc);
    expect(off.keys).toEqual(['findings', 'summary', 'metadata']);
    expect(off.json).not.toContain('schemaVersion');
    process.env[FLAG] = '1';
    const on = emitScanJson({ ...doc, experimental: { note: 'local' } });
    expect(on.keys).toContain('experimental');
    expect(on.keys).not.toContain('schemaVersion');
    expect(emitScanJson(doc).json).toContain('experimental');
    expect(validateScanDocument(null)).toEqual(['scan document must be an object']);
    expect(validateScanDocument([])).toEqual(['scan document must be an object']);
    expect(validateScanDocument('nope')).toEqual(['scan document must be an object']);
    expect(validateScanDocument({ summary: {}, metadata: {} })).toEqual(['missing findings']);
    expect(validateScanDocument({ findings: [], summary: {} })).toEqual(['missing metadata']);
    expect(() => assertSemverCompatible([...STABLE_REQUIRED], [...STABLE_REQUIRED])).not.toThrow();
    delete process.env[FLAG];
  });
});
