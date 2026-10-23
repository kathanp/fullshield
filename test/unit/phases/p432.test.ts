import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, REACH_PROPERTY, renderBom, validateCycloneDx16, type BomRequest } from '../../../src/phases/p432.js';

afterEach(() => {
  delete process.env[FLAG];
});

function request(over: Partial<BomRequest> = {}): BomRequest {
  return {
    name: 'app',
    version: '1.0.0',
    components: [
      { name: 'left-pad', version: '1.0.0', reachClass: 'reachable', hash: { alg: 'SHA-256', content: 'abc' } },
      { name: 'ms', version: '2.0.0' },
    ],
    spec: '1.6',
    ...over,
  };
}

describe('phase 432 CycloneDX 1.6', () => {
  it('emits the 1.5 document when the flag is off', () => {
    expect(enabled()).toBe(false);
    const doc = renderBom(request());
    expect(doc.specVersion).toBe('1.5');
    const components = doc.components as Array<Record<string, unknown>>;
    expect(components[0]).not.toHaveProperty('properties');
    expect(components[0]).not.toHaveProperty('hashes');
  });

  it('emits a 1.6 component with a reachability property and a hash', () => {
    process.env[FLAG] = '1';
    const doc = renderBom(request());
    expect(validateCycloneDx16(doc)).toEqual([]);
    expect(doc.specVersion).toBe('1.6');
    const components = doc.components as Array<Record<string, unknown>>;
    expect(components[0]?.properties).toEqual([{ name: REACH_PROPERTY, value: 'reachable' }]);
    expect(components[0]?.hashes).toEqual([{ alg: 'SHA-256', content: 'abc' }]);
    expect(components[1]).not.toHaveProperty('properties');
    expect(components[1]).not.toHaveProperty('hashes');
  });

  it('stays on 1.5 unless the caller asks for spec 1.6', () => {
    process.env[FLAG] = '1';
    expect(renderBom(request({ spec: '1.5' })).specVersion).toBe('1.5');
    expect(renderBom(request({ spec: undefined })).specVersion).toBe('1.5');
    expect(validateCycloneDx16({ bomFormat: 'CycloneDX' })).toEqual([
      'specVersion must be "1.6"',
      'components must be an array',
    ]);
  });

  it('keeps a purl and a license on the 1.5 document and rejects a non-object', () => {
    process.env[FLAG] = '1';
    const doc = renderBom(request({
      spec: '1.5',
      components: [
        { name: 'left-pad', version: '1.0.0', purl: 'pkg:npm/left-pad@1.0.0', license: 'MIT' },
        { name: 'ms', version: '2.0.0', purl: 'pkg:npm/ms@2.0.0' },
        { name: 'debug', version: '4.0.0', license: 'MIT' },
      ],
    }));
    const components = doc.components as Array<Record<string, unknown>>;
    expect(components[0]?.purl).toBe('pkg:npm/left-pad@1.0.0');
    expect(components[0]?.licenses).toEqual([{ license: { id: 'MIT' } }]);
    expect(components[2]?.licenses).toEqual([{ license: { id: 'MIT' } }]);
    expect(validateCycloneDx16(null)).toEqual(['CycloneDX document must be an object']);
    expect(validateCycloneDx16([])).toEqual(['CycloneDX document must be an object']);
    expect(validateCycloneDx16({ bomFormat: 'nope', specVersion: '1.6', components: [] })).toContain('bomFormat must be "CycloneDX"');
    delete process.env[FLAG];
  });
});
