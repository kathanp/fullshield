import { vi } from 'vitest';

const calls = vi.hoisted(() => ({ n: 0 }));

vi.mock('../../../src/core/engine.js', () => ({
  scan: () => {
    calls.n += 1;
    return Promise.resolve({
      findings: [{ ruleId: `R${calls.n}`, file: 'a.js', line: 1, severity: 'high' }],
    });
  },
}));

import { describe, expect, it } from 'vitest';

import { byteMatch, main, threeRuns } from '../../../src/phases/p480.js';

const DETSTRESS = 'FULLSHIELD_EXPERIMENTAL_DETSTRESS';

async function capture(run: () => Promise<number>): Promise<{ code: number; stderr: string }> {
  let stderr = '';
  const writeErr = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: string | Uint8Array) => {
    stderr += String(chunk);
    return true;
  });
  try {
    const code = await run();
    return { code, stderr };
  } finally {
    process.stderr.write = writeErr;
  }
}

describe('phase 480 differing runs', () => {
  it('reports finding bytes that differ across the three pools', async () => {
    process.env[DETSTRESS] = '1';
    calls.n = 0;
    try {
      const runs = await threeRuns('/tmp/fs480-mismatch');
      expect(byteMatch(runs)).toBe(false);
      const result = await capture(() => main(['--dir', '/tmp/fs480-mismatch']));
      expect(result.code).toBe(1);
      expect(result.stderr).toContain('finding bytes differ');
    } finally {
      delete process.env[DETSTRESS];
    }
  });
});
