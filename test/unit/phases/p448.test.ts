import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { childProcesses, exportNames, FLAG, ITERATOR_DOC, scanFindingsIterator, scanJson } from '../../../src/phases/p448.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const findings = [
  { ruleId: 'B', file: 'a.js', line: 2, severity: 'high' },
  { ruleId: 'A', file: 'a.js', line: 9, severity: 'low' },
];

describe('phase 448', () => {
  it('matches scan JSON after sorting', async () => {
    process.env[FLAG] = '1';
    const streamed = [];
    for await (const finding of scanFindingsIterator(findings)) {
      streamed.push(finding);
    }
    streamed.sort((left, right) => left.ruleId.localeCompare(right.ruleId) || left.line - right.line);
    expect(streamed).toEqual(scanJson(findings));
    expect(ITERATOR_DOC).toContain('not the scan --json order');
  });

  it('leaves no child process after cancel', async () => {
    process.env[FLAG] = '1';
    const controller = new AbortController();
    const streamed = [];
    for await (const finding of scanFindingsIterator(findings, controller.signal)) {
      streamed.push(finding);
      controller.abort();
    }
    expect(streamed).toHaveLength(1);
    expect(childProcesses()).toEqual([]);
    const src = readFileSync(join(root, 'src/phases/p448.ts'), 'utf8');
    expect(src.includes('child_process')).toBe(false);
  });

  it('omits the iterator from the export list when the flag is off', () => {
    expect(exportNames()).not.toContain('scanFindingsIterator');
  });
});
