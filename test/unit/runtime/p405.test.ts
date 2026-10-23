import { describe, expect, it } from 'vitest';

import { enabled, FLAG, runCompatibilityMatrix } from '../../../src/runtime/exp/p405.js';

describe('phase 405 runtime matrix', () => {
  it('adds nothing when the flag is off', async () => {
    expect(enabled()).toBe(false);
    const matrix = await runCompatibilityMatrix();
    expect(matrix.cells).toEqual([]);
    expect(matrix.unreviewed).toBe(true);
  });

  it('passes http.Server and express and lists the missing frameworks', async () => {
    process.env[FLAG] = '1';
    const matrix = await runCompatibilityMatrix();
    const byName = new Map(matrix.cells.map((cell) => [cell.framework, cell]));
    expect(byName.get('http.Server')?.status).toBe('pass');
    expect(byName.get('express')?.status).toBe('pass');
    expect(byName.get('fastify')?.status).toBe('not-in-matrix');
    expect(byName.get('koa')?.status).toBe('not-in-matrix');
    expect(byName.get('next')?.status).toBe('not-in-matrix');
    expect(byName.get('next')?.reason).toContain('network install');
    expect(matrix.unreviewed).toBe(true);
    expect(matrix.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });
});
