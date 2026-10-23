import { afterEach, describe, expect, it } from 'vitest';

import { GUARD_FLAG, guardsEnabled, regexClears, sinkStillReports } from '../../../src/engine/guards.js';

afterEach(() => {
  delete process.env[GUARD_FLAG];
});

function fn(body: string): string {
  return `function save(x) {\n${body}\n}\n`;
}

describe('phase 258 guards', () => {
  it('is off unless the flag is set', () => {
    expect(guardsEnabled()).toBe(false);
    expect(sinkStillReports(fn('db.query(x);'), 'x', 'sqli')).toBe(false);
  });

  it('clears a dominating guard and still reports the negative cases', () => {
    process.env[GUARD_FLAG] = '1';
    const bare = fn('db.query(x);');
    expect(sinkStillReports(bare, 'x', 'sqli')).toBe(true);

    const allow = fn('const allowlist = ["a", "b"];\nif (!allowlist.includes(x)) return;\ndb.query(x);');
    expect(sinkStillReports(allow, 'x', 'sqli')).toBe(false);

    const eqs = fn('if (!(x === \'a\' || x === \'b\')) return;\ndb.query(x);');
    expect(sinkStillReports(eqs, 'x', 'sqli')).toBe(false);

    const anchored = fn('if (!/^[a-z0-9_-]+$/.test(x)) return;\ndb.query(x);');
    expect(regexClears('/^[a-z0-9_-]+$/', 'sqli')).toBe(true);
    expect(sinkStillReports(anchored, 'x', 'sqli')).toBe(false);

    const pathGuard = fn('if (!path.resolve(base, x).startsWith(base + path.sep)) return;\nfs.readFile(x);');
    expect(sinkStillReports(pathGuard.replace('fs.readFile(x)', 'db.query(x)'), 'x', 'path')).toBe(false);

    const typed = fn('if (typeof x !== \'number\') return;\ndb.query(x);');
    expect(sinkStillReports(typed, 'x', 'sqli')).toBe(false);

    const otherVar = fn('const allowlist = ["a"];\nif (!allowlist.includes(y)) return;\ndb.query(x);');
    expect(sinkStillReports(otherVar, 'x', 'sqli')).toBe(true);

    const nested = fn('const allowlist = ["a"];\nif (flag) {\nif (!allowlist.includes(x)) return;\n}\ndb.query(x);');
    expect(sinkStillReports(nested, 'x', 'sqli')).toBe(true);

    const unanchored = fn('if (!/[a-z0-9_-]+/.test(x)) return;\ndb.query(x);');
    expect(regexClears('/[a-z0-9_-]+/', 'sqli')).toBe(false);
    expect(sinkStillReports(unanchored, 'x', 'sqli')).toBe(true);

    const prefixBug = fn('if (!path.resolve(base, x).startsWith(base)) return;\ndb.query(x);');
    expect(sinkStillReports(prefixBug, 'x', 'path')).toBe(true);
  });
});
