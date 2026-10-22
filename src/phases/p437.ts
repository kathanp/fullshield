/**
 * Phase 437. MCP tools for routes and witnesses.
 * Off unless FULLSHIELD_EXPERIMENTAL_MCP2=1.
 * Flag off: the new tools are not registered.
 * Fix stays a dry-run unless the caller passes apply.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_MCP2';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface McpTool {
  name: string;
  description: string;
}

export interface WitnessRecord {
  id: string;
  source: string;
  sink: string;
  proof: Record<string, unknown>;
}

export interface ToolResult {
  isError: boolean;
  code?: string;
  body: Record<string, unknown>;
}

export const TOOLS: readonly McpTool[] = [
  { name: 'route_matrix', description: 'Return the route matrix JSON the CLI writes.' },
  { name: 'get_witness', description: 'Return one witness. Fixes are dry-run unless the user passes apply.' },
  { name: 'proof_json', description: 'Return the proof JSON for a finding id.' },
  { name: 'fix', description: 'Dry-run. Does not apply unless apply is passed.' },
];

export function toolManifest(): { tools: readonly McpTool[] } {
  if (!enabled()) {
    return { tools: [] };
  }
  return { tools: TOOLS };
}

export function callTool(
  name: string,
  args: Record<string, unknown>,
  data: { routes: unknown; witnesses: readonly WitnessRecord[] },
): ToolResult {
  if (!enabled()) {
    return { isError: true, code: 'FS-E', body: {} };
  }
  if (name === 'route_matrix') {
    return { isError: false, body: { routes: data.routes } };
  }
  if (name === 'get_witness' || name === 'proof_json') {
    const id = typeof args.id === 'string' ? args.id : '';
    const found = data.witnesses.find((row) => row.id === id);
    if (found === undefined) {
      return { isError: true, code: 'unknown_id', body: { message: `unknown witness ${id}` } };
    }
    return { isError: false, body: name === 'get_witness' ? { witness: found } : { proof: found.proof } };
  }
  if (name === 'fix') {
    const apply = args.apply === true;
    return { isError: false, body: { dryRun: !apply, applied: apply } };
  }
  return { isError: true, code: 'unknown_tool', body: { message: name } };
}
