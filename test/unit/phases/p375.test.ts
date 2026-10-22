import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { enabled, FLAG, urlImports } from '../../../src/phases/p375.js';

describe('phase 375 import maps', () => {
  it('adds nothing when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(urlImports('import "https://cdn.example.invalid/a.js";', null).findings).toEqual([]);
  });

  it('reports an https specifier without integrity and strips the query', () => {
    process.env[FLAG] = '1';
    const result = urlImports('', JSON.stringify({ imports: { app: 'https://cdn.example.invalid/a.js?x=1' } }));
    expect(result.findings.some((row) => row.specifier === 'https://cdn.example.invalid/a.js' && row.severity === 'medium')).toBe(true);
  });

  it('does not report the same specifier when integrity is present', () => {
    process.env[FLAG] = '1';
    const spec = 'https://cdn.example.invalid/a.js';
    const result = urlImports('', JSON.stringify({ imports: { app: spec }, integrity: { [spec]: 'sha512-aaaaaaaa' } }));
    expect(result.findings.filter((row) => row.specifier === spec)).toEqual([]);
  });

  it('does not report a relative specifier or a comment', () => {
    process.env[FLAG] = '1';
    const source = '// https://cdn.example.invalid/nope.js\nimport "./local.js";\n';
    expect(urlImports(source, JSON.stringify({ imports: { app: './local.js' } })).findings).toEqual([]);
  });

  it('reports a data URL at high', () => {
    process.env[FLAG] = '1';
    const result = urlImports('import "data:text/javascript,1";', null);
    expect(result.findings[0]?.severity).toBe('high');
  });

  it('reports a broken map at medium and records the event', () => {
    process.env[FLAG] = '1';
    const result = urlImports('', '{');
    expect(result.events.map((event) => event.code)).toEqual(['271']);
    expect(result.findings.some((row) => row.severity === 'medium')).toBe(true);
  });

  it('does not fetch', () => {
    const source = readFileSync(new URL('../../../src/phases/p375.ts', import.meta.url), 'utf8');
    expect(source).not.toContain('node:http');
  });
});
