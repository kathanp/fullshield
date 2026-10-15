import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { createOfficialMcpServer } from '../../../src/mcp/index.js';

const clean = join(process.cwd(), 'test', 'fixtures', 'clean-app');
const vuln = join(process.cwd(), 'test', 'fixtures', 'vulnerable-app');

describe('harden-6 official MCP SDK client', () => {
  it('lists and calls every tool through the SDK client handshake', async () => {
    const server = await createOfficialMcpServer({ experimental: true });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'fullshield-test', version: '0.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const listed = await client.listTools();
      const names = listed.tools.map((t) => t.name).sort();
      expect(names).toEqual(['explain_finding', 'get_findings', 'propose_fix', 'scan', 'verify_fix']);

      const scan = await client.callTool({
        name: 'scan',
        arguments: { path: vuln, offline: true, modules: ['config'] },
      });
      expect(JSON.stringify(scan)).toMatch(/CONFIG-HELMET-001/);

      const findings = await client.callTool({ name: 'get_findings', arguments: {} });
      expect(JSON.stringify(findings)).toMatch(/CONFIG-/);

      const explained = await client.callTool({
        name: 'explain_finding',
        arguments: { ruleId: 'CONFIG-HELMET-001' },
      });
      expect(JSON.stringify(explained).length).toBeGreaterThan(10);

      const proposed = await client.callTool({
        name: 'propose_fix',
        arguments: { ruleId: 'CONFIG-BODYLIMIT-001' },
      });
      expect(JSON.stringify(proposed)).toMatch(/100kb|wrote/);

      const verified = await client.callTool({
        name: 'verify_fix',
        arguments: { ruleId: 'CONFIG-BODYLIMIT-001' },
      });
      expect(JSON.stringify(verified)).toMatch(/originalUntouched|tempApplied/);

      const cleanScan = await client.callTool({
        name: 'scan',
        arguments: { path: clean, offline: true },
      });
      expect(JSON.stringify(cleanScan)).toBeDefined();
    } finally {
      await client.close();
      await server.close();
    }
  });
});
