import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { createProgram } from '../../../../src/cli/program.js';
import { mappingFor } from '../../../../src/compliance/index.js';
import { scan } from '../../../../src/core/engine.js';
import { guardTools, scanMcpConfig } from '../../../../src/modules/mcp/index.js';
import { runSastOnText } from '../../../../src/modules/sast/engine.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_MCPCFG';
const mcpApp = join(process.cwd(), 'test', 'fixtures', 'mcp-app');
const mcpClean = join(process.cwd(), 'test', 'fixtures', 'mcp-clean');

const MCP_IDS = ['MCP-001', 'MCP-002', 'MCP-003', 'MCP-004', 'MCP-005'] as const;

let previousFlag: string | undefined;
let previousHome: string | undefined;
let previousUserProfile: string | undefined;
const tempHomes: string[] = [];

beforeEach(() => {
  previousFlag = process.env[FLAG];
  previousHome = process.env.HOME;
  previousUserProfile = process.env.USERPROFILE;
  delete process.env[FLAG];
});

afterEach(() => {
  if (previousFlag === undefined) delete process.env[FLAG];
  else process.env[FLAG] = previousFlag;
  if (previousHome === undefined) delete process.env.HOME;
  else process.env.HOME = previousHome;
  if (previousUserProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = previousUserProfile;
  for (const dir of tempHomes.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function poisonedHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'fullshield-mcp-home-'));
  tempHomes.push(home);
  mkdirSync(join(home, '.cursor'), { recursive: true });
  writeFileSync(
    join(home, '.cursor', 'mcp.json'),
    JSON.stringify({
      mcpServers: {
        home: {
          command: 'npx',
          args: ['evil-mcp@latest'],
          env: { HOME_SECRET: 'inline-home-secret-Ab3dEf9hIjKlMnOpQrStUv' },
          url: 'http://home.example.invalid/mcp',
        },
      },
    }),
    'utf8',
  );
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  return home;
}

describe('Phase 33 MCP config rules (experimental)', () => {
  it('is a no-op without FULLSHIELD_EXPERIMENTAL_MCPCFG', () => {
    const findings = scanMcpConfig(mcpApp);
    expect(findings).toEqual([]);
  });

  it('flags MCP-001 inline secrets in env (not env refs)', () => {
    const findings = scanMcpConfig(mcpApp, { experimental: true });
    expect(findings.some((f) => f.ruleId === 'MCP-001')).toBe(true);
    const hit = findings.find((f) => f.ruleId === 'MCP-001');
    expect(hit?.severity).toBe('high');
    expect(hit?.snippet ?? '').not.toContain('inline-not-from-env-Ab3dEf9hIjKlMnOpQrStUvWx');
  });

  it('flags MCP-002 unpinned npx / @latest', () => {
    const findings = scanMcpConfig(mcpApp, { experimental: true });
    expect(findings.some((f) => f.ruleId === 'MCP-002')).toBe(true);
    expect(findings.find((f) => f.ruleId === 'MCP-002')?.severity).toBe('medium');
  });

  it('flags MCP-003 unrestricted filesystem-write / shell tools without an allowlist', () => {
    const findings = scanMcpConfig(mcpApp, { experimental: true });
    expect(findings.some((f) => f.ruleId === 'MCP-003')).toBe(true);
    expect(findings.find((f) => f.ruleId === 'MCP-003')?.severity).toBe('medium');
  });

  it('flags MCP-004 instruction-injection / hidden / zero-width tool descriptions', () => {
    const findings = scanMcpConfig(mcpApp, { experimental: true });
    expect(findings.some((f) => f.ruleId === 'MCP-004')).toBe(true);
    expect(findings.find((f) => f.ruleId === 'MCP-004')?.severity).toBe('high');
  });

  it('flags MCP-005 remote MCP over plain http://', () => {
    const findings = scanMcpConfig(mcpApp, { experimental: true });
    expect(findings.some((f) => f.ruleId === 'MCP-005')).toBe(true);
    expect(findings.find((f) => f.ruleId === 'MCP-005')?.severity).toBe('medium');
  });

  it('does not flag the negative fixture', () => {
    const findings = scanMcpConfig(mcpClean, { experimental: true });
    expect(findings.filter((f) => f.ruleId.startsWith('MCP-'))).toEqual([]);
  });

  it('does not scan the home directory without --include-home', () => {
    const home = poisonedHome();
    const findings = scanMcpConfig(mcpClean, { experimental: true, includeHome: false });
    expect(findings.filter((f) => f.ruleId.startsWith('MCP-'))).toEqual([]);
    expect(findings.some((f) => (f.file ?? '').includes(home))).toBe(false);
    const implicit = scanMcpConfig(mcpClean, { experimental: true });
    expect(implicit.filter((f) => f.ruleId.startsWith('MCP-'))).toEqual([]);
  });

  it('scans home MCP configs only when includeHome is set', () => {
    const home = poisonedHome();
    const findings = scanMcpConfig(mcpClean, { experimental: true, includeHome: true });
    expect(findings.some((f) => f.ruleId === 'MCP-001')).toBe(true);
    expect(findings.some((f) => f.ruleId === 'MCP-002')).toBe(true);
    expect(findings.some((f) => f.ruleId === 'MCP-005')).toBe(true);
    expect(findings.some((f) => (f.file ?? '').includes('.cursor'))).toBe(true);
    expect(homedir()).toBe(home);
  });

  it('never performs network I/O', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = () => {
      throw new Error('network forbidden');
    };
    try {
      expect(() => scanMcpConfig(mcpApp, { experimental: true })).not.toThrow();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe('Phase 33 default scan wiring', () => {
  it('emits no MCP-* IDs from default scan without the experimental flag', async () => {
    const result = await scan({ cwd: mcpApp, modules: ['sast', 'config'] });
    expect(result.findings.filter((f) => f.ruleId.startsWith('MCP-'))).toEqual([]);
  });

  it('emits MCP-* IDs from scan() when FULLSHIELD_EXPERIMENTAL_MCPCFG=1', async () => {
    process.env[FLAG] = '1';
    const result = await scan({ cwd: mcpApp, modules: ['sast', 'config'] });
    const ids = new Set(result.findings.map((f) => f.ruleId));
    for (const id of MCP_IDS) {
      expect(ids.has(id)).toBe(true);
    }
  });

  it('does not read HOME during scan() without --include-home', async () => {
    poisonedHome();
    process.env[FLAG] = '1';
    const result = await scan({ cwd: mcpClean, modules: ['config'] });
    expect(result.findings.filter((f) => f.ruleId.startsWith('MCP-'))).toEqual([]);
  });

  it('scan --include-home is registered and still emits no MCP-* without the flag', async () => {
    const program = createProgram();
    const scanCmd = program.commands.find((c) => c.name() === 'scan');
    expect(scanCmd?.options.map((o) => o.long)).toContain('--include-home');
    expect(scanCmd?.options.map((o) => o.long)).toContain('--experimental-mcpcfg');
    poisonedHome();
    const result = await scan({ cwd: mcpClean, modules: ['config'], includeHome: true });
    expect(result.findings.filter((f) => f.ruleId.startsWith('MCP-'))).toEqual([]);
  });
});

describe('Phase 33 MCP server taint (model-provided tool args)', () => {
  const handler = `
    import { exec } from 'node:child_process';
    export function register(server) {
      server.tool('run', { cmd: 'string' }, async ({ cmd }) => {
        exec(cmd);
      });
    }
  `;

  it('does not treat MCP tool args as taint when the flag is off', async () => {
    const findings = await runSastOnText('server.js', handler);
    expect(findings.some((f) => f.ruleId === 'SAST-CMDI-001')).toBe(false);
  });

  it('treats MCP tool handler arguments as taint sources when the flag is on', async () => {
    process.env[FLAG] = '1';
    const findings = await runSastOnText('server.js', handler);
    expect(findings.some((f) => f.ruleId === 'SAST-CMDI-001')).toBe(true);
  });

  it('does not flag an MCP tool that does not send args to a sink', async () => {
    process.env[FLAG] = '1';
    const findings = await runSastOnText(
      'server.js',
      `
      export function register(server) {
        server.tool('search', { q: 'string' }, async ({ q }) => {
          return { content: [{ type: 'text', text: String(q) }] };
        });
      }
      `,
    );
    expect(findings.some((f) => f.ruleId === 'SAST-CMDI-001')).toBe(false);
  });
});

describe('Phase 33 guardTools', () => {
  it('denies dangerous tools that are not allowlisted and logs the call', async () => {
    const log: Array<{ tool: string; result: string }> = [];
    const wrapped = guardTools(
      [{ name: 'shell', execute: () => 'pwned' }],
      { allow: ['search'], log: (e) => log.push({ tool: e.tool, result: e.result }) },
    );
    const shell = wrapped[0];
    expect(shell).toBeDefined();
    await expect(shell!.execute('id')).rejects.toThrow(/denied/i);
    expect(log).toEqual([{ tool: 'shell', result: 'denied' }]);
  });

  it('requires confirm for write/payment tools even when allowlisted', async () => {
    const log: Array<{ tool: string; result: string }> = [];
    let confirmed = false;
    const wrapped = guardTools(
      [{ name: 'write_file', execute: () => 'wrote' }],
      {
        allow: ['write_file'],
        confirm: () => confirmed,
        log: (e) => log.push({ tool: e.tool, result: e.result }),
      },
    );
    const write = wrapped[0];
    expect(write).toBeDefined();
    await expect(write!.execute('/tmp/x', 'a')).rejects.toThrow(/confirm/i);
    expect(log.some((e) => e.result === 'unconfirmed')).toBe(true);
    confirmed = true;
    await expect(write!.execute('/tmp/x', 'a')).resolves.toBe('wrote');
    expect(log.some((e) => e.result === 'ok')).toBe(true);
  });

  it('runs an allowlisted read tool and logs success', async () => {
    const log: Array<{ tool: string; result: string }> = [];
    const wrapped = guardTools([{ name: 'search', execute: (q: unknown) => `hit:${String(q)}` }], {
      allow: ['search'],
      log: (e) => log.push({ tool: e.tool, result: e.result }),
    });
    const search = wrapped[0];
    expect(search).toBeDefined();
    await expect(search!.execute('docs')).resolves.toBe('hit:docs');
    expect(log).toEqual([{ tool: 'search', result: 'ok' }]);
  });
});

describe('Phase 33 compliance rows', () => {
  it('maps MCP-001 through MCP-005', () => {
    for (const id of MCP_IDS) {
      const row = mappingFor(id);
      expect(row?.ruleId).toBe(id);
      expect(row?.cwe.startsWith('CWE-')).toBe(true);
    }
  });
});
