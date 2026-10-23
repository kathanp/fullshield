import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p287.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 287', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeStored('db.query("1");').findings).toEqual([]);
  });

  it('does not report a literal query as stored input', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeStored('db.query("select 1");').findings).toEqual([]);
  });

  it('reports stored reads at sql, xss, command, and template sinks', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeStored(':::').findings).toEqual([]);
    const source = [
      'function run(req) {',
      '  const row = db.findOne(id);',
      '  const listed = repo.find({ id });',
      '  const got = cache.get("k");',
      '  const fresh = db.query("select 1");',
      '  const skipped = db.save(row);',
      '  const tainted = db.query(req.query.id);',
      '  db.query(row.name);',
      '  db.execute(listed.id + "x");',
      '  res.send(got);',
      '  res.write(`${row.html}`);',
      '  cp.exec(row.cmd);',
      '  cp.execSync(row.cmd);',
      '  view.render(row.tpl);',
      '  db.query("select ?", row.id);',
      '  db.query("select $1", row.id);',
      '  if (cond) db.query(row.id);',
      '  if (cond) { db.query(row.id); }',
      '  db.query(call(row));',
      '  console.log(row);',
      '  db.query(...row);',
      '  { db.query(row); }',
      '}',
    ].join('\n');
    const kinds = phase.analyzeStored(source).findings.map((row) => row.sinkClass);
    expect(kinds).toContain('sqli');
    expect(kinds).toContain('xss');
    expect(kinds).toContain('cmdi');
    expect(kinds).toContain('ssti');
    delete process.env[phase.FLAG];
  });
});
