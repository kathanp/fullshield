import { describe, expect, it } from 'vitest';

import { FLAG, FsError, loadPlugin, runPlugin } from '../../../src/phases/p449.js';

const plugin = JSON.stringify({
  ruleId: 'USER-SQL-001',
  sources: ['req.query'],
  sinks: [{ pattern: 'db.query', sinkClass: 'sqli' }],
  sanitizers: [{ pattern: 'sqlEscape', clears: ['sqli'] }],
});

describe('phase 449', () => {
  it('reports a USER rule id for a matching sink', () => {
    process.env[FLAG] = '1';
    const loaded = loadPlugin('/plugins', 'sql.json', plugin);
    const findings = runPlugin(loaded, 'a.js', "db.query(req.query.id);", '/plugins/sql.json');
    expect(findings[0]?.ruleId).toBe('USER-SQL-001');
  });

  it('rejects javascript, a shadowed rule id, and a path that escapes', () => {
    expect(() => loadPlugin('/plugins', 'sql.js', plugin)).toThrow(FsError);
    expect(() => loadPlugin('/plugins', 'sql.json', plugin.replace('USER-SQL-001', 'SAST-SQLI-001'))).toThrow(/USER-/);
    expect(() => loadPlugin('/plugins', '../sql.json', plugin)).toThrow(/escapes/);
  });

  it('names the plugin file when a sanitizer clears SQL', () => {
    process.env[FLAG] = '1';
    const loaded = loadPlugin('/plugins', 'sql.json', plugin);
    const findings = runPlugin(loaded, 'a.js', "sqlEscape(id);\ndb.query(id);", '/plugins/sql.json');
    expect(findings[0]?.witness.cleared).toBe('sqli');
    expect(findings[0]?.witness.pluginPath).toBe('/plugins/sql.json');
  });

  it('reports nothing from the plugin when the flag is off', () => {
    const loaded = loadPlugin('/plugins', 'sql.json', plugin);
    expect(runPlugin(loaded, 'a.js', 'db.query(id);', '/plugins/sql.json')).toEqual([]);
  });
});
