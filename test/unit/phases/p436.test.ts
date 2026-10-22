import { afterEach, describe, expect, it } from 'vitest';

import {
  diagnosticKeys,
  enabled,
  FLAG,
  handleLsp,
  lspBinding,
  scanKeys,
  type Diagnostic,
} from '../../../src/phases/p436.js';

afterEach(() => {
  delete process.env[FLAG];
});

const file = 'file:///q.js';
const openSink = 'db.query("SELECT " + name);\n';
const closedSink = 'db.query("SELECT ?", [name]);\n';

describe('phase 436 language server', () => {
  it('errors with FS-E when the flag is off', () => {
    expect(enabled()).toBe(false);
    expect(handleLsp({ id: 9, method: 'initialize' })).toEqual({
      jsonrpc: '2.0',
      id: 9,
      error: { code: 'FS-E', message: 'FS-E lsp is experimental' },
    });
    expect(lspBinding()).toEqual({ port: null, tcp: false });
  });

  it('returns the same SQL key as scan JSON', () => {
    process.env[FLAG] = '1';
    expect(handleLsp({ id: 1, method: 'initialize' })).toEqual({
      jsonrpc: '2.0',
      id: 1,
      result: { capabilities: { diagnosticProvider: true } },
    });
    expect(handleLsp({ id: 2, method: 'shutdown' })).toEqual({ jsonrpc: '2.0', id: 2, result: null });
    const response = handleLsp({
      id: 3,
      method: 'textDocument/diagnostic',
      params: { textDocument: { uri: file, text: openSink } },
    });
    const items = (response.result as { items: Diagnostic[] }).items;
    expect(items).toEqual([{ code: 'SAST-SQLI-001', message: 'SAST-SQLI-001', line: 1, file }]);
    expect(diagnosticKeys(items)).toEqual(scanKeys(file, openSink));
    expect(response).not.toHaveProperty('log');
  });

  it('emits nothing for a bound query, a parse error, or an unknown method', () => {
    process.env[FLAG] = '1';
    const clean = handleLsp({
      id: 4,
      method: 'textDocument/diagnostic',
      params: { textDocument: { uri: file, text: closedSink } },
    });
    expect(clean.result).toEqual({ items: [] });
    expect(scanKeys(file, closedSink)).toEqual([]);
    const broken = handleLsp({
      id: 5,
      method: 'textDocument/diagnostic',
      params: { textDocument: { uri: file, text: 'function (' } },
    });
    expect(broken.result).toEqual({ items: [] });
    expect(typeof broken.log).toBe('string');
    expect(handleLsp({ id: 6, method: 'workspace/symbol' })).toEqual({
      jsonrpc: '2.0',
      id: 6,
      error: { code: 'method-not-found', message: 'workspace/symbol' },
    });
  });
});
