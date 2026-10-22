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
});
