import { afterEach, describe, expect, it } from 'vitest';

import { enabled, FLAG, renderSarif, sarifErrors, type SarifEdit } from '../../../src/phases/p425.js';

afterEach(() => {
  delete process.env[FLAG];
});

function edit(over: Partial<SarifEdit> = {}): SarifEdit {
  return {
    ruleId: 'SAST-SQLI-001',
    message: 'token AKIAIOSFODNN7EXAMPLE',
    file: 'src/db.js',
    line: 3,
    patch: 'use AKIAIOSFODNN7EXAMPLE',
    disposition: 'safe',
    refused: false,
    ...over,
  };
}

interface SarifDoc {
  version: string;
  runs: Array<{ results: Array<{ message: { text: string }; fixes?: Array<{ description: { text: string }; artifactChanges: Array<{ replacements: Array<{ insertedContent: { text: string } }> }> }> }> }>;
}

function docOf(text: string): SarifDoc {
  return JSON.parse(text) as SarifDoc;
}

describe('phase 425 SARIF fixes', () => {
  it('omits fixes when the flag is off', () => {
    expect(enabled()).toBe(false);
    const doc = docOf(renderSarif([edit()]));
    expect(doc.version).toBe('2.1.0');
    expect(doc.runs[0]?.results[0]).not.toHaveProperty('fixes');
    expect(sarifErrors(renderSarif([edit()]))).toEqual([]);
  });

  it('attaches a scrubbed fix for an edit that was not refused', () => {
    process.env[FLAG] = '1';
    const text = renderSarif([edit()]);
    const doc = docOf(text);
    const row = doc.runs[0]?.results[0];
    expect(row?.message.text).toBe('token AKIA****');
    expect(row?.fixes?.[0]?.description.text).toBe('safe');
    expect(row?.fixes?.[0]?.artifactChanges[0]?.replacements[0]?.insertedContent.text).toBe('use AKIA****');
    expect(text).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(sarifErrors(text)).toEqual([]);
  });

  it('omits fixes for a refused edit', () => {
    process.env[FLAG] = '1';
    const doc = docOf(renderSarif([edit({ refused: true, disposition: 'review' })]));
    expect(doc.runs[0]?.results[0]).not.toHaveProperty('fixes');
    expect(doc.runs[0]?.results[0]?.message.text).toBe('token AKIA****');
  });
});
