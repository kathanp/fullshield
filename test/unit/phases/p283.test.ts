import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p283.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 283', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzePath('fs.readFile(req.query.p);').findings).toEqual([]);
  });

  it('reports a request path and ignores a literal path', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzePath('fs.readFile(req.query.p);').findings.length).toBeGreaterThan(0);
    expect(phase.analyzePath('fs.readFile("notes.txt");').findings).toEqual([]);
    expect(phase.projectTargetsWindows({})).toBe(false);
  });

  it('joins, resolves, and guards paths on windows and posix', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzePath(':::').findings).toEqual([]);
    expect(phase.projectTargetsWindows({ engines: { os: 'win32' } })).toBe(true);
    expect(phase.projectTargetsWindows({ dependencies: { electron: '1.0.0' } })).toBe(true);
    const source = [
      'function f(req) {',
      '  const name = req.query.p;',
      '  const abs = "C:\\\\windows";',
      '  let next = name;',
      '  next = path.join(base, name);',
      '  path.normalize(name);',
      '  path.resolve(name, abs);',
      '  path.basename(name);',
      '  fs.readFile(base + name);',
      '  fs.readFile(path.join("dir", name));',
      '  fs.readFile(path.resolve(abs, name));',
      '  fs.readFile(join(base, name));',
      '  fs.readFile((0, foo)(name));',
      '  fs.readFile(name ? name : "x");',
      '  readFile(name);',
      '  fs.readFileSync(next);',
      '  res.sendFile(name);',
      '  fs.open(name);',
      '  fs.readFile(`${name}`);',
      '  if (cond) { fs.readFile(name); }',
      '  if (name.startsWith(root + path.sep)) { fs.readFile(name); }',
      '  if (name.startsWith(root + ("/" + "x"))) { fs.readFile(name); }',
      '  if (name.startsWith(root + "dir")) { fs.readFile(name); }',
      '  if (name.startsWith(root + "/")) fs.readFile(name);',
      '  else fs.readFile(name);',
      '  fs.readFile(...args);',
      '}',
    ].join('\n');
    expect(phase.analyzePath(source).findings.length).toBeGreaterThan(0);
    expect(phase.analyzePath(source, { windows: true }).findings.length).toBeGreaterThan(0);
    delete process.env[phase.FLAG];
  });
});
