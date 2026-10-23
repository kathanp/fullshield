/**
 * Phase 436. Language server on stdio.
 * Off unless FULLSHIELD_EXPERIMENTAL_LSP=1.
 * Flag off: the subcommand errors with FS-E.
 * Diagnostics come from the same keys as scan JSON. This module binds no TCP port.
 */
import { parse } from '@typescript-eslint/typescript-estree';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_LSP';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface ScanKey {
  ruleId: string;
  file: string;
  line: number;
  severity: 'high';
}

export interface Diagnostic {
  code: string;
  message: string;
  line: number;
  file: string;
}

export interface LspMessage {
  jsonrpc?: '2.0';
  id?: number;
  method?: string;
  params?: unknown;
}

export interface LspResponse {
  jsonrpc: '2.0';
  id: number | null;
  result?: unknown;
  error?: { code: string; message: string };
  log?: string;
}

export function lspBinding(): { port: null; tcp: false } {
  return { port: null, tcp: false };
}

function scanJson(file: string, text: string): ScanKey[] {
  const keys: ScanKey[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((line, index) => {
    if (/\.query\s*\(/.test(line) && (/\+\s*[A-Za-z_$]/.test(line) || /\$\{/.test(line))) {
      keys.push({ ruleId: 'SAST-SQLI-001', file, line: index + 1, severity: 'high' });
    }
  });
  return keys;
}

function diagnostics(text: string, file: string): { items: Diagnostic[]; log?: string } {
  try {
    parse(text, { loc: true, range: false, jsx: false });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'parse failure';
    return { items: [], log: message };
  }
  return {
    items: scanJson(file, text).map((key) => ({
      code: key.ruleId,
      message: key.ruleId,
      line: key.line,
      file: key.file,
    })),
  };
}

function fileFrom(params: unknown): { file: string; text: string } {
  if (typeof params !== 'object' || params === null) {
    return { file: 'untitled.js', text: '' };
  }
  const record = params as Record<string, unknown>;
  const doc = record.textDocument;
  if (typeof doc !== 'object' || doc === null) {
    return { file: 'untitled.js', text: '' };
  }
  const body = doc as Record<string, unknown>;
  const uri = typeof body.uri === 'string' ? body.uri : 'untitled.js';
  const text = typeof body.text === 'string' ? body.text : '';
  return { file: uri, text };
}

export function handleLsp(message: LspMessage): LspResponse {
  if (!enabled()) {
    return { jsonrpc: '2.0', id: message.id ?? null, error: { code: 'FS-E', message: 'FS-E lsp is experimental' } };
  }
  const id = message.id ?? null;
  if (message.method === 'initialize') {
    return { jsonrpc: '2.0', id, result: { capabilities: { diagnosticProvider: true } } };
  }
  if (message.method === 'shutdown') {
    return { jsonrpc: '2.0', id, result: null };
  }
  if (message.method === 'textDocument/diagnostic') {
    const doc = fileFrom(message.params);
    const found = diagnostics(doc.text, doc.file);
    return { jsonrpc: '2.0', id, result: { items: found.items }, ...(found.log !== undefined ? { log: found.log } : {}) };
  }
  return { jsonrpc: '2.0', id, error: { code: 'method-not-found', message: message.method ?? '' } };
}

export function diagnosticKeys(items: readonly Diagnostic[]): string[] {
  return items.map((item) => `${item.code}\0${item.file}\0${item.line}\0high`);
}

export function scanKeys(file: string, text: string): string[] {
  return scanJson(file, text).map((key) => `${key.ruleId}\0${key.file}\0${key.line}\0${key.severity}`);
}
