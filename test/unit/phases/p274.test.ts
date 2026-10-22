import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p274.js';


afterEach(() => {
  delete process.env[phase.FLAG];
});

const hierarchy = `class Base { run(id) { db.query(id); } }
class Child extends Base {}
function main() {
  const obj = new Child();
  obj.run(req.query.id);
}
`;

describe('phase 274', () => {
  it('returns no findings when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeHierarchy(hierarchy).findings).toEqual([]);
  });

  it('resolves an inherited method and ignores a literal argument', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeHierarchy(hierarchy).findings.length).toBeGreaterThan(0);
    const literal = hierarchy.replace('req.query.id', "'ok'");
    expect(phase.analyzeHierarchy(literal).findings).toEqual([]);
  });
});
