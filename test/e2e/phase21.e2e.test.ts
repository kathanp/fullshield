import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const cli = join(root, 'dist', 'cli', 'index.js');

describe('Phase 21 CLI MCP (built)', () => {
  it('refuses mcp without FULLSHIELD_EXPERIMENTAL_MCP', () => {
    const result = spawnSync(process.execPath, [cli, 'mcp', '--list-tools'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_MCP: '' },
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/FULLSHIELD_EXPERIMENTAL_MCP/);
  });

  it('lists read-only tools and answers tools/list JSON-RPC', () => {
    const listed = spawnSync(process.execPath, [cli, 'mcp', '--list-tools'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, FULLSHIELD_EXPERIMENTAL_MCP: '1' },
    });
    expect(listed.status).toBe(0);
    expect(listed.stdout).toMatch(/propose_fix/);
    expect(listed.stdout).toMatch(/scan/);
    const rpc = spawnSync(
      process.execPath,
      [cli, 'mcp'],
      {
        cwd: root,
        encoding: 'utf8',
        input: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
        env: { ...process.env, FULLSHIELD_EXPERIMENTAL_MCP: '1' },
      },
    );
    expect(rpc.status).toBe(0);
    const parsed = JSON.parse(rpc.stdout) as { result: { tools: Array<{ name: string }> } };
    expect(parsed.result.tools.map((t) => t.name)).toContain('verify_fix');
  });
});
