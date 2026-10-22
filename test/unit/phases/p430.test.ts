import { afterEach, describe, expect, it } from 'vitest';

import {
  assertMapping,
  enabled,
  FLAG,
  FsError,
  mapCwe,
  parseFrontMatter,
  renderTaxonomy,
  type MappedRule,
} from '../../../src/phases/p430.js';

afterEach(() => {
  delete process.env[FLAG];
});

function fenced(body: string): string {
  return `---\n${body}\n---\n`;
}

const rules: MappedRule[] = [
  { id: 'SAST-SQLI-001', cwe: ['89'], title: 'CWE-79' },
  { id: 'STYLE-001', cwe: ['none'], title: 'style', reason: 'not a weakness' },
];

describe('phase 430 SARIF taxonomies', () => {
  it('returns the SARIF text unchanged when the flag is off', () => {
    expect(enabled()).toBe(false);
    const base = '{\n  "version": "2.1.0"\n}';
    expect(renderTaxonomy(base, rules)).toBe(base);
  });

  it('maps CWE from front matter and skips none', () => {
    process.env[FLAG] = '1';
    const parsed = parseFrontMatter(fenced('id: SAST-SQLI-001\ncwe:\n  - "89"'));
    expect(parsed).toEqual({ id: 'SAST-SQLI-001', cwe: ['89'] });
    expect(mapCwe({ title: 'CWE-79', frontMatter: parsed ?? undefined })).toEqual(['89']);
    const text = renderTaxonomy('{"version":"2.1.0"}', rules);
    const doc = JSON.parse(text) as { taxonomies: Array<{ name: string; rules: Array<{ ruleId: string; cwe: string }> }> };
    expect(doc.taxonomies).toEqual([{ name: 'CWE', rules: [{ ruleId: 'SAST-SQLI-001', cwe: '89' }] }]);
  });

  it('refuses a title-only mapping and a none token without a reason', () => {
    process.env[FLAG] = '1';
    expect(() => mapCwe({ title: 'CWE-89' })).toThrow(FsError);
    expect(() => mapCwe({ title: 'CWE-89' })).toThrow('refusing to map CWE from the title alone');
    const none = parseFrontMatter(fenced('id: STYLE-001\ncwe: none'));
    expect(assertMapping(none)).toEqual(['cwe: none requires a reason']);
    expect(() => mapCwe({ title: 'style', frontMatter: none ?? undefined })).toThrow('cwe: none requires a reason');
    expect(renderTaxonomy('[]', rules)).toBe('[]');
    expect(parseFrontMatter('no fence')).toBeNull();
  });
});
