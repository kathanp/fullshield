import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { makeFindingId, type Finding, type Severity } from '../../core/finding.js';
import { maskSecret, shannonEntropy } from '../secrets/mask.js';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_MCPCFG';
const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', 'coverage']);
const SECRET_NAME = /(key|secret|token|passw(or)?d|pwd|credential|auth)/i;
const ENV_REF = /^\s*(?:\$\{[A-Za-z_][\w]*\}|\$[A-Za-z_][\w]*|%[A-Za-z_][\w]*%)\s*$/;
const INJECT_PHRASE =
  /ignore previous|ignore all previous|hidden instruction|do not tell (?:the )?user|you are now|system prompt/i;
const ZERO_WIDTH = /[\u200B\u200C\u200D\uFEFF\u2060\u202E\u2066\u2067\u2068\u2069]|\\u(?:200b|200c|200d|feff|2060|202e|206[6-9])/i;
const DANGEROUS_TOOL =
  /\.(?:tool|registerTool|addTool)\(\s*['"`](shell|exec|bash|cmd|run_command|execute|write_file|writeFile|fs_write)['"`]/i;
const ALLOWLIST = /allowed(?:Directories|Paths|Commands|Roots)|allowlist/;
const FS_PKG = /server-filesystem|mcp-filesystem/i;
const SHELL_PKG = /server-shell|mcp-server-commands|mcp-shell|server-everything/i;
const NPX = /^(npx|bunx|pnpx)(?:\.cmd)?$/i;
const DLX_CMD = /^(pnpm|yarn|npm)(?:\.cmd)?$/i;

export function mcpCfgEnabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface McpScanOptions {
  experimental?: boolean;
  includeHome?: boolean;
}

function finding(
  ruleId: string,
  title: string,
  message: string,
  file: string,
  severity: Severity,
  extra: { line?: number; snippet?: string; remediation: string; cwe: string },
): Finding {
  return {
    id: makeFindingId(ruleId, file, `${extra.line ?? 0}|${extra.snippet ?? message}`),
    ruleId,
    module: 'config',
    title,
    severity,
    confidence: 'medium',
    cwe: extra.cwe,
    file,
    line: extra.line,
    snippet: extra.snippet,
    message,
    remediation: extra.remediation,
  };
}

function lineOf(text: string, needle: string): number {
  const idx = text.indexOf(needle);
  if (idx < 0) {return 1;}
  return text.slice(0, idx).split(/\r?\n/).length;
}

function stripJsonc(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(stripJsonc(text)) as unknown;
  } catch {
    return undefined;
  }
}

function commandBase(command: unknown): string {
  if (typeof command !== 'string') {return '';}
  const norm = command.replaceAll('\\', '/');
  return norm.split('/').pop() ?? command;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {return [];}
  return value.filter((v): v is string => typeof v === 'string');
}

function isNpmSpec(spec: string): boolean {
  if (spec.startsWith('-') || spec.startsWith('.') || spec.startsWith('/') || spec.includes('\\')) {return false;}
  if (spec.includes('://') || /\.[cm]?[jt]sx?$/.test(spec)) {return false;}
  return true;
}

function specUnpinned(spec: string): boolean {
  if (!isNpmSpec(spec)) {return false;}
  if (/@latest(?:[/]|$)/i.test(spec) || spec.endsWith('@*')) {return true;}
  const rest = spec.startsWith('@') ? spec.slice(1) : spec;
  const at = rest.lastIndexOf('@');
  if (at > 0) {
    const ver = rest.slice(at + 1);
    if (/^\d/.test(ver)) {return false;}
    if (ver === 'latest' || ver === '*') {return true;}
  }
  return /^(@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/.test(spec);
}

function looksSecretValue(value: string): boolean {
  if (ENV_REF.test(value)) {return false;}
  if (/\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36})\b/.test(value)) {return true;}
  if (value.length >= 20 && shannonEntropy(value) > 4.5) {return true;}
  return value.length >= 12;
}

function unrestrictedPath(path: string): boolean {
  const n = path.replaceAll('\\', '/').trim();
  return n === '/' || n === '/*' || n === '*' || n === '~' || /^[A-Za-z]:\/?$/.test(path);
}

function pathAllowArgs(args: string[]): string[] {
  const out: string[] = [];
  for (const arg of args) {
    if (arg.startsWith('-') || specUnpinned(arg) || /^(@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+@/.test(arg)) {continue;}
    if (arg.startsWith('.') || arg.startsWith('/') || arg.includes('\\') || arg === '~' || arg === '*') {
      out.push(arg);
    }
  }
  return out;
}

function hasAllowlist(server: Record<string, unknown>, text: string): boolean {
  for (const key of ['allowedDirectories', 'allowedPaths', 'allowedCommands', 'roots', 'allowlist', 'allow']) {
    const v = server[key];
    if (Array.isArray(v) && v.length > 0 && !v.every((p) => typeof p === 'string' && unrestrictedPath(p))) {
      return true;
    }
  }
  return ALLOWLIST.test(text);
}

interface ServerEntry {
  name: string;
  server: Record<string, unknown>;
}

function serverEntries(root: unknown): ServerEntry[] {
  if (root === null || typeof root !== 'object' || Array.isArray(root)) {return [];}
  const obj = root as Record<string, unknown>;
  const block = obj.mcpServers ?? obj.servers;
  if (block === null || typeof block !== 'object' || Array.isArray(block)) {return [];}
  const out: ServerEntry[] = [];
  for (const [name, value] of Object.entries(block as Record<string, unknown>)) {
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      out.push({ name, server: value as Record<string, unknown> });
    }
  }
  return out;
}

function visitStrings(value: unknown, visit: (key: string, val: string) => void, key = ''): void {
  if (typeof value === 'string') {
    visit(key, value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {visitStrings(item, visit, key);}
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {visitStrings(v, visit, k);}
  }
}

function isMcpConfigRel(rel: string, name: string): boolean {
  const n = rel.replaceAll('\\', '/');
  if (name === '.mcp.json' || n.endsWith('/.mcp.json')) {return true;}
  if (name === 'claude_desktop_config.json') {return true;}
  if (name === 'mcp.json' && (n === '.cursor/mcp.json' || n.endsWith('/.cursor/mcp.json'))) {return true;}
  if (name === 'mcp.json' && (n === '.vscode/mcp.json' || n.endsWith('/.vscode/mcp.json'))) {return true;}
  return false;
}

function isSourceName(name: string): boolean {
  return /\.[cm]?[jt]sx?$/.test(name);
}

function collectRepoFiles(dir: string, out: Array<{ abs: string; rel: string }> = [], rel = ''): Array<{ abs: string; rel: string }> {
  if (!existsSync(dir)) {return out;}
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {continue;}
    const childRel = rel === '' ? entry.name : `${rel}/${entry.name}`;
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) {continue;}
      collectRepoFiles(abs, out, childRel);
    } else if (entry.isFile()) {
      if (isMcpConfigRel(childRel, entry.name) || isSourceName(entry.name)) {
        out.push({ abs, rel: childRel });
      }
    }
  }
  return out;
}

/** Home MCP client config paths. Call only when `--include-home` is set. */
export function mcpHomeConfigPaths(home: string): string[] {
  const paths = [join(home, '.cursor', 'mcp.json'), join(home, '.vscode', 'mcp.json'), join(home, '.mcp.json')];
  if (process.platform === 'darwin') {
    paths.push(join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'));
  } else if (process.platform === 'win32') {
    const appData = process.env.APPDATA ?? join(home, 'AppData', 'Roaming');
    paths.push(join(appData, 'Claude', 'claude_desktop_config.json'));
  } else {
    paths.push(join(home, '.config', 'Claude', 'claude_desktop_config.json'));
  }
  return paths;
}

function scanJsonConfig(file: string, text: string, findings: Finding[]): void {
  const parsed = parseJson(text);
  for (const { server } of serverEntries(parsed)) {
    const args = asStringArray(server.args);
    const cmd = commandBase(server.command);
    const env = server.env;
    if (env !== null && typeof env === 'object' && !Array.isArray(env)) {
      for (const [key, value] of Object.entries(env)) {
        if (typeof value !== 'string' || ENV_REF.test(value)) {continue;}
        if (!SECRET_NAME.test(key) && !looksSecretValue(value)) {continue;}
        findings.push(
          finding(
            'MCP-001',
            'Secret inlined in MCP config',
            'MCP server env has an inline secret; use an environment-variable reference instead.',
            file,
            'high',
            {
              line: lineOf(text, key),
              snippet: maskSecret(value),
              remediation: 'Replace inline secrets with env refs such as ${GITHUB_TOKEN} and rotate the exposed value.',
              cwe: 'CWE-798',
            },
          ),
        );
      }
    }

    const npxish = NPX.test(cmd) || (DLX_CMD.test(cmd) && args.some((a) => a === 'dlx' || a === 'exec'));
    if (npxish && args.some((a) => specUnpinned(a))) {
      findings.push(
        finding(
          'MCP-002',
          'Unpinned npx MCP server',
          'MCP server is launched via unpinned npx / @latest (supply-chain risk).',
          file,
          'medium',
          {
            line: lineOf(text, 'npx') || lineOf(text, '@latest'),
            snippet: args.find((a) => specUnpinned(a))?.slice(0, 80),
            remediation: 'Pin the MCP server package to an exact version (pkg@1.2.3), not @latest or a bare name.',
            cwe: 'CWE-494',
          },
        ),
      );
    }

    const joinedArgs = args.join(' ');
    const commandText = typeof server.command === 'string' ? server.command : '';
    const fsServer = FS_PKG.test(joinedArgs) || FS_PKG.test(commandText);
    const shellServer = SHELL_PKG.test(joinedArgs) || SHELL_PKG.test(commandText);
    const paths = pathAllowArgs(args);
    const unrestrictedFs = fsServer && (paths.length === 0 || paths.some(unrestrictedPath));
    if ((unrestrictedFs || shellServer) && !hasAllowlist(server, text)) {
      findings.push(
        finding(
          'MCP-003',
          'MCP shell/exec or unrestricted filesystem tool',
          'MCP server exposes shell/exec or unrestricted filesystem writes without an allowlist.',
          file,
          'medium',
          {
            line: lineOf(text, args[0] ?? 'mcp'),
            remediation: 'Restrict filesystem roots to project directories and deny shell/exec tools unless an allowlist is enforced.',
            cwe: 'CWE-250',
          },
        ),
      );
    }
  }

  visitStrings(parsed, (key, val) => {
    if (key === 'description' && (INJECT_PHRASE.test(val) || ZERO_WIDTH.test(val) || val.includes('<!--'))) {
      findings.push(
        finding(
          'MCP-004',
          'MCP tool description instruction injection',
          'Tool description contains instruction-injection text, hidden markup, or zero-width characters.',
          file,
          'high',
          {
            line: lineOf(text, val.slice(0, 24)) || lineOf(text, 'description'),
            snippet: val.replace(ZERO_WIDTH, '').slice(0, 80),
            remediation: 'Keep tool descriptions literal and user-facing; strip hidden/zero-width characters and model-directed instructions.',
            cwe: 'CWE-74',
          },
        ),
      );
    }
    if ((key === 'url' || key === 'serverUrl' || key === 'href' || key === 'endpoint') && /^http:\/\//i.test(val.trim())) {
      findings.push(
        finding(
          'MCP-005',
          'Remote MCP over plaintext HTTP',
          'Remote MCP server is configured with http:// instead of https://.',
          file,
          'medium',
          {
            line: lineOf(text, val),
            snippet: val.slice(0, 80),
            remediation: 'Use https:// for remote MCP servers so tokens and tool traffic are not sent in the clear.',
            cwe: 'CWE-319',
          },
        ),
      );
    }
  });
}

function scanServerSource(file: string, text: string, findings: Finding[]): void {
  if (!/\.(?:tool|registerTool|addTool)\s*\(/.test(text) && !/@modelcontextprotocol/.test(text)) {return;}
  if (DANGEROUS_TOOL.test(text) && !ALLOWLIST.test(text)) {
    findings.push(
      finding(
        'MCP-003',
        'MCP shell/exec or unrestricted filesystem tool',
        'MCP server code registers shell/exec or filesystem-write tools without an allowlist.',
        file,
        'medium',
        {
          line: lineOf(text, 'tool('),
          remediation: 'Do not expose shell/exec or unrestricted writes; gate them with an allowlist and a confirm step (see guardTools).',
          cwe: 'CWE-250',
        },
      ),
    );
  }
  if (INJECT_PHRASE.test(text) || ZERO_WIDTH.test(text)) {
    findings.push(
      finding(
        'MCP-004',
        'MCP tool description instruction injection',
        'MCP tool description contains instruction-injection text, hidden markup, or zero-width characters.',
        file,
        'high',
        {
          line: lineOf(text, 'Ignore previous') || lineOf(text, 'ignore previous'),
          remediation: 'Keep tool descriptions literal and user-facing; strip hidden/zero-width characters and model-directed instructions.',
          cwe: 'CWE-74',
        },
      ),
    );
  }
}

function scanOne(abs: string, file: string, findings: Finding[]): void {
  let text: string;
  try {
    text = readFileSync(abs, 'utf8');
  } catch {
    return;
  }
  if (text.length > 1024 * 1024 || text.includes('\u0000')) {return;}
  if (file.endsWith('.json') || file.endsWith('.mcp.json')) {scanJsonConfig(file, text, findings);}
  else {scanServerSource(file, text, findings);}
}

/** Experimental MCP client-config + server-code rules. Off unless experimental. No network. */
export function scanMcpConfig(dir: string, opts: McpScanOptions = {}): Finding[] {
  if (!opts.experimental && !mcpCfgEnabled()) {return [];}
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {return [];}
  const findings: Finding[] = [];
  for (const file of collectRepoFiles(dir)) {
    scanOne(file.abs, file.rel, findings);
  }
  if (opts.includeHome === true) {
    for (const abs of mcpHomeConfigPaths(homedir())) {
      if (!existsSync(abs) || !statSync(abs).isFile()) {continue;}
      scanOne(abs, abs, findings);
    }
  }
  return findings;
}

export interface GuardToolCall {
  tool: string;
  args: unknown;
  result: 'ok' | 'denied' | 'unconfirmed';
}

export interface GuardTool {
  name: string;
  description?: string;
  execute: (...args: unknown[]) => unknown;
}

const DENY = /^(shell|exec|bash|cmd|eval|run_command)$/i;
const CONFIRM = /write|payment|pay|transfer|purchase/i;

/**
 * Optional runtime wrapper for LLM/MCP tools: deny-list dangerous capabilities,
 * require `confirm` for writes/payments, and log every call.
 */
export function guardTools(
  tools: readonly GuardTool[],
  opts: {
    allow?: readonly string[];
    confirm?: (tool: string, args: unknown) => boolean | Promise<boolean>;
    log?: (event: GuardToolCall) => void;
  } = {},
): GuardTool[] {
  const allow = opts.allow !== undefined ? new Set(opts.allow) : undefined;
  return tools.map((tool) => ({
    ...tool,
    execute: async (...args: unknown[]) => {
      if (DENY.test(tool.name) || (allow !== undefined && !allow.has(tool.name))) {
        opts.log?.({ tool: tool.name, args, result: 'denied' });
        throw new Error(`tool ${tool.name} denied`);
      }
      if (CONFIRM.test(tool.name)) {
        const ok = opts.confirm ? await opts.confirm(tool.name, args) : false;
        if (!ok) {
          opts.log?.({ tool: tool.name, args, result: 'unconfirmed' });
          throw new Error(`tool ${tool.name} requires confirm`);
        }
      }
      opts.log?.({ tool: tool.name, args, result: 'ok' });
      return tool.execute(...args);
    },
  }));
}
