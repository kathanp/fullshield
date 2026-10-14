import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import { scan } from '../core/engine.js';
import type { Finding, ModuleName } from '../core/finding.js';
import { proposeFix, applyUnifiedDiff } from '../fixer/patches.js';
import { scanLlmApp } from '../llm/index.js';

export interface McpTool {
  name: string;
  description: string;
}

export interface McpSession {
  experimental: boolean;
  findings: Finding[];
  cwd?: string;
}

export function createMcpSession(opts: { experimental?: boolean } = {}): McpSession {
  return {
    experimental: opts.experimental === true || process.env.FULLSHIELD_EXPERIMENTAL_MCP === '1',
    findings: [],
  };
}

export function listMcpTools(): McpTool[] {
  return [
    { name: 'scan', description: 'Run a FullShield scan (read-only)' },
    { name: 'get_findings', description: 'Return findings from the last scan in this session' },
    { name: 'explain_finding', description: 'Explain a finding by ruleId (text only)' },
    { name: 'propose_fix', description: 'Return a unified diff; never writes files' },
    { name: 'verify_fix', description: 'Apply the diff in a temp copy and rescan; original tree untouched' },
  ];
}

interface ToolArgs {
  path?: string;
  offline?: boolean;
  modules?: ModuleName[];
  ruleId?: string;
}

export async function callMcpTool(
  session: McpSession,
  name: string,
  args: ToolArgs = {},
): Promise<unknown> {
  if (!session.experimental) return { skipped: true };
  if (name === 'scan') {
    const cwd = resolve(args.path ?? session.cwd ?? process.cwd());
    session.cwd = cwd;
    const result = await scan({ cwd, offline: args.offline === true, modules: args.modules });
    const llm = scanLlmApp(cwd, { experimental: true });
    session.findings = [...result.findings, ...llm];
    return { findings: session.findings, summary: result.summary };
  }
  if (name === 'get_findings') {
    return { findings: session.findings };
  }
  if (name === 'explain_finding') {
    const hit = session.findings.find((f) => f.ruleId === args.ruleId);
    if (!hit) return { text: `no finding ${args.ruleId}` };
    return { text: `${hit.title}: ${hit.message} ${hit.remediation}` };
  }
  if (name === 'propose_fix') {
    return proposeOnly(session, args.ruleId);
  }
  if (name === 'verify_fix') {
    return verifyInTemp(session, args.ruleId);
  }
  return { error: `unknown tool ${name}` };
}

function proposeOnly(session: McpSession, ruleId: string | undefined): { diff: string; wrote: boolean } {
  const hit = session.findings.find((f) => f.ruleId === ruleId);
  if (!hit?.file || !session.cwd) return { diff: '', wrote: false };
  const abs = join(session.cwd, hit.file);
  const source = readFileSync(abs, 'utf8');
  const proposal = proposeFix(hit, source);
  return { diff: proposal?.diff ?? '', wrote: false };
}

function verifyInTemp(
  session: McpSession,
  ruleId: string | undefined,
): { originalUntouched: boolean; tempApplied: boolean } {
  const hit = session.findings.find((f) => f.ruleId === ruleId);
  if (!hit?.file || !session.cwd) return { originalUntouched: true, tempApplied: false };
  const original = join(session.cwd, hit.file);
  const before = readFileSync(original, 'utf8');
  const mtime = statSync(original).mtimeMs;
  const proposal = proposeFix(hit, before);
  if (!proposal?.diff) return { originalUntouched: true, tempApplied: false };
  const tmp = mkdtempSync(join(tmpdir(), 'fullshield-mcp-verify-'));
  try {
    cpSync(session.cwd, tmp, { recursive: true });
    const copy = join(tmp, hit.file);
    const next = applyUnifiedDiff(readFileSync(copy, 'utf8'), proposal.diff);
    writeFileSync(copy, next);
    const untouched = readFileSync(original, 'utf8') === before && statSync(original).mtimeMs === mtime;
    return { originalUntouched: untouched, tempApplied: next !== before };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

export interface JsonRpcRequest {
  jsonrpc?: string;
  id?: number | string;
  method?: string;
  params?: { name?: string; arguments?: ToolArgs };
}

export async function handleMcpRequest(session: McpSession, req: JsonRpcRequest): Promise<unknown> {
  const id = req.id ?? null;
  if (req.method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'fullshield', version: '0.1.0' } },
    };
  }
  if (req.method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: listMcpTools() } };
  }
  if (req.method === 'tools/call') {
    const name = req.params?.name ?? '';
    const result = await callMcpTool(session, name, req.params?.arguments ?? {});
    return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(result) }] } };
  }
  return { jsonrpc: '2.0', id, error: { code: -32601, message: `unknown method ${req.method}` } };
}

function textResult(value: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return { content: [{ type: 'text', text: JSON.stringify(value) }] };
}

/** Official MCP SDK server (stdio / in-memory). Tools stay read-only. */
export function createOfficialMcpServer(opts: { experimental?: boolean } = {}): McpServer {
  const session = createMcpSession(opts);
  const server = new McpServer({ name: 'fullshield', version: '0.1.0' });
  const modulesSchema = z.array(z.enum(['deps', 'secrets', 'sast', 'config'])).optional();
  server.registerTool(
    'scan',
    {
      description: 'Run a FullShield scan (read-only)',
      inputSchema: {
        path: z.string().optional(),
        offline: z.boolean().optional(),
        modules: modulesSchema,
      },
    },
    async (args) => textResult(await callMcpTool(session, 'scan', args)),
  );
  server.registerTool(
    'get_findings',
    { description: 'Return findings from the last scan in this session', inputSchema: {} },
    async () => textResult(await callMcpTool(session, 'get_findings', {})),
  );
  server.registerTool(
    'explain_finding',
    {
      description: 'Explain a finding by ruleId (text only)',
      inputSchema: { ruleId: z.string() },
    },
    async (args) => textResult(await callMcpTool(session, 'explain_finding', args)),
  );
  server.registerTool(
    'propose_fix',
    {
      description: 'Return a unified diff; never writes files',
      inputSchema: { ruleId: z.string() },
    },
    async (args) => textResult(await callMcpTool(session, 'propose_fix', args)),
  );
  server.registerTool(
    'verify_fix',
    {
      description: 'Apply the diff in a temp copy and rescan; original tree untouched',
      inputSchema: { ruleId: z.string() },
    },
    async (args) => textResult(await callMcpTool(session, 'verify_fix', args)),
  );
  return server;
}

export async function startMcpStdio(opts: { experimental?: boolean } = {}): Promise<void> {
  const server = createOfficialMcpServer(opts);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
