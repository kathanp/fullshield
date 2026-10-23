import { afterEach, describe, expect, it } from 'vitest';

import * as phase from '../../../src/phases/p288.js';

afterEach(() => {
  delete process.env[phase.FLAG];
});

describe('phase 288', () => {
  it('returns nothing when the flag is off', () => {
    expect(phase.enabled()).toBe(false);
    expect(phase.analyzeStoredLink('res.send("ok");').findings).toEqual([]);
  });

  it('does not report a literal response', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeStoredLink('res.send("ok");').findings).toEqual([]);
  });

  it('links a stored write to a later read on another route', () => {
    process.env[phase.FLAG] = '1';
    expect(phase.analyzeStoredLink(':::').findings).toEqual([]);
    const source = [
      'app.post("/save", (req) => { User.create({ name: req.body.name, age: 1 }); });',
      'app.get("/show", () => { const row = User.findOne(); res.send(row.name); res.write(row.age); });',
      'app.put("/other", () => { const row = Note.find(); res.send(row.body); });',
      'app.patch("/skip", () => { res.send("ok"); });',
      'app.delete(id, () => {});',
    ].join('\n');
    const result = phase.analyzeStoredLink(source);
    expect(result.findings.some((row) => row.confidence === 'high')).toBe(true);
    expect(result.findings.some((row) => row.confidence === 'medium')).toBe(true);
    delete process.env[phase.FLAG];
  });
});
