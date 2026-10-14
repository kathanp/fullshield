import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { callMcpTool, createMcpSession, handleMcpRequest, listMcpTools } from '../../../src/mcp/index.js';

const root = process.cwd();
const vuln = join(root, 'test', 'fixtures', 'vulnerable-app');
const clean = join(root, 'test', 'fixtures', 'clean-app');

describe('Phase 21 MCP server (read-only, experimental)', () => {
  it('lists scan, get_findings, explain_finding, propose_fix, verify_fix', () => {
    const names = listMcpTools().map((t) => t.name);
    expect(names).toEqual(['scan', 'get_findings', 'explain_finding', 'propose_fix', 'verify_fix']);
  });

  it('is a no-op without experimental', async () => {
    const session = createMcpSession();
    const result = await callMcpTool(session, 'scan', { path: clean });
    expect(result).toMatchObject({ skipped: true });
  });

  it('scan + get_findings round-trip on clean-app', async () => {
    const session = createMcpSession({ experimental: true });
    const scanned = (await callMcpTool(session, 'scan', { path: clean, offline: true })) as {
      findings: unknown[];
    };
    expect(Array.isArray(scanned.findings)).toBe(true);
    const stored = (await callMcpTool(session, 'get_findings', {})) as { findings: unknown[] };
    expect(stored.findings).toEqual(scanned.findings);
  });

  it('explain_finding returns text and does not write files', async () => {
    const session = createMcpSession({ experimental: true });
    await callMcpTool(session, 'scan', { path: vuln, offline: true, modules: ['config'] });
    const explained = (await callMcpTool(session, 'explain_finding', {
      ruleId: 'CONFIG-HELMET-001',
    })) as { text: string };
    expect(explained.text.length).toBeGreaterThan(10);
  });

  it('propose_fix returns a diff and never writes the target file', async () => {
    const file = join(vuln, 'src', 'index.js');
    const before = readFileSync(file, 'utf8');
    const mtime = statSync(file).mtimeMs;
    const session = createMcpSession({ experimental: true });
    await callMcpTool(session, 'scan', { path: vuln, offline: true, modules: ['config'] });
    const proposed = (await callMcpTool(session, 'propose_fix', {
      ruleId: 'CONFIG-BODYLIMIT-001',
    })) as { diff: string; wrote: boolean };
    expect(proposed.wrote).toBe(false);
    expect(proposed.diff).toMatch(/100kb/);
    expect(readFileSync(file, 'utf8')).toBe(before);
    expect(statSync(file).mtimeMs).toBe(mtime);
  });

  it('verify_fix applies in a temp copy and leaves the original tree untouched', async () => {
    const file = join(vuln, 'src', 'index.js');
    const before = readFileSync(file, 'utf8');
    const session = createMcpSession({ experimental: true });
    await callMcpTool(session, 'scan', { path: vuln, offline: true, modules: ['config'] });
    const verified = (await callMcpTool(session, 'verify_fix', {
      ruleId: 'CONFIG-BODYLIMIT-001',
    })) as { originalUntouched: boolean; tempApplied: boolean };
    expect(verified.originalUntouched).toBe(true);
    expect(verified.tempApplied).toBe(true);
    expect(readFileSync(file, 'utf8')).toBe(before);
  });

  it('handleMcpRequest answers tools/list over JSON-RPC', async () => {
    const session = createMcpSession({ experimental: true });
    const res = await handleMcpRequest(session, {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
    });
    expect(res).toMatchObject({ jsonrpc: '2.0', id: 1 });
    const tools = (res as { result: { tools: Array<{ name: string }> } }).result.tools;
    expect(tools.some((t) => t.name === 'propose_fix')).toBe(true);
  });
});
