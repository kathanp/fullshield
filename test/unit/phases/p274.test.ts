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

  it('resolves prototype methods, inherits, and mixins', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeHierarchy(':::').findings).toEqual([]);
    const source = [
      'function Base() {}',
      'Base.prototype.run = function (id) { db.query(id + "x"); };',
      'function Child() {}',
      'inherits(Child, Base);',
      'function Loop() {}',
      'inherits(Loop, Loop);',
      'const mixin = { extra: function (id) { db.query(`${id}`); } };',
      'Object.assign(Child.prototype, mixin);',
      'Object.assign(Child.prototype, { late: function (id) { db.query(id); } });',
      'Object.assign(Child.prototype);',
      'function main() {',
      '  let obj = new Child();',
      '  obj = new Child();',
      '  obj.run(req.query.id);',
      '  obj.extra(req.query.id);',
      '  obj.late("no");',
      '  obj.missing(req.query.id);',
      '  { obj.run(req.query.id); }',
      '}',
      'const bag = { skip: 1, go: function (id) { db.query(id); } };',
    ].join('\n');
    expect(phase.analyzeHierarchy(source).findings.length).toBeGreaterThan(0);
    delete process.env[phase.FLAG];
  });
});
