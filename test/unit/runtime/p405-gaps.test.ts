import type { IncomingMessage, ServerResponse } from 'node:http';

import { afterEach, describe, expect, it, vi } from 'vitest';

const gate = vi.hoisted(() => ({
  http: 'ok',
  express: 'missing',
  calls: 0,
}));

vi.mock('node:http', () => ({
  createServer(handler: (req: IncomingMessage, res: ServerResponse) => void) {
    const res = { statusCode: 200, end() {} };
    handler({} as IncomingMessage, res as ServerResponse);
    handler({ url: '/attack' } as IncomingMessage, res as ServerResponse);
    return {
      listen(_port: number, _host: string, callback: () => void) {
        callback();
      },
      address() {
        return 'pipe';
      },
      close(callback: () => void) {
        callback();
      },
    };
  },
  get(_options: unknown, callback: (res: { statusCode?: number; resume: () => void; on: (event: string, fn: () => void) => void }) => void) {
    if (gate.http === 'string-error') {
      return { on(event: string, fn: (err: unknown) => void) { if (event === 'error') {fn('boom');} } };
    }
    const statusCode = gate.http === 'bare' ? undefined : gate.http === 'mismatch' ? 200 : gate.calls % 2 === 0 ? 200 : 403;
    gate.calls += 1;
    callback({
      statusCode,
      resume() {},
      on(event: string, fn: () => void) {
        if (event === 'end') {fn();}
      },
    });
    return { on() {} };
  },
}));

vi.mock('node:module', () => {
  function requireMock(name: string): unknown {
    if (name !== 'express') {throw new Error(`missing ${name}`);}
    if (gate.express === 'bad') {return { not: 'a function' };}
    if (gate.express === 'string') {
      const failed = new Error('express failed');
      Object.setPrototypeOf(failed, null);
      throw failed;
    }
    throw new Error('missing express');
  }
  requireMock.resolve = (name: string) => {
    if (name === 'express' && gate.express !== 'missing') {return '/virtual/express.js';}
    throw new Error(`missing ${name}`);
  };
  return { createRequire: () => requireMock };
});

import { FLAG, runCompatibilityMatrix } from '../../../src/runtime/exp/p405.js';

afterEach(() => {
  delete process.env[FLAG];
  gate.http = 'ok';
  gate.express = 'missing';
  gate.calls = 0;
});

describe('phase 405 failure cells', () => {
  it('passes http when the mocked address is not a port and lists express as absent', async () => {
    process.env[FLAG] = '1';
    const matrix = await runCompatibilityMatrix();
    const http = matrix.cells.find((cell) => cell.framework === 'http.Server');
    const express = matrix.cells.find((cell) => cell.framework === 'express');
    expect(http?.status).toBe('pass');
    expect(express?.status).toBe('not-in-matrix');
  });

  it('fails http on a status mismatch and express when the export is not a function', async () => {
    process.env[FLAG] = '1';
    gate.http = 'mismatch';
    gate.express = 'bad';
    const matrix = await runCompatibilityMatrix();
    const http = matrix.cells.find((cell) => cell.framework === 'http.Server');
    const express = matrix.cells.find((cell) => cell.framework === 'express');
    expect(http?.status).toBe('fail');
    expect(http?.reason).toContain('benign=');
    expect(express?.status).toBe('fail');
    expect(express?.reason).toContain('not a function');
  });

  it('fails http when status is missing and express when the loader throws a string', async () => {
    process.env[FLAG] = '1';
    gate.http = 'bare';
    gate.express = 'string';
    const matrix = await runCompatibilityMatrix();
    expect(matrix.cells.find((cell) => cell.framework === 'http.Server')?.status).toBe('fail');
    const express = matrix.cells.find((cell) => cell.framework === 'express');
    expect(express?.status).toBe('fail');
    expect(express?.reason).toBe('failed');
  });

  it('fails http when the request errors with a string', async () => {
    process.env[FLAG] = '1';
    gate.http = 'string-error';
    gate.express = 'missing';
    const matrix = await runCompatibilityMatrix();
    const http = matrix.cells.find((cell) => cell.framework === 'http.Server');
    expect(http?.status).toBe('fail');
    expect(http?.reason).toBe('failed');
  });
});
