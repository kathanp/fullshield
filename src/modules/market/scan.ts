import { readdir, readFile } from 'node:fs/promises';
import { basename, join } from 'node:path';

import { makeFindingId, type Finding, type ModuleName, type Severity } from '../../core/finding.js';
import { attachParents, calleeName, literalString, propName, walk } from '../sast/ast.js';
import { analyzeFile, nodeIsTainted } from '../sast/taint.js';
import type { AstNode } from '../sast/types.js';

const RSC_NAMES = ['react-server-dom-webpack', 'react-server-dom-parcel', 'react-server-dom-turbopack'] as const;
const RSC_VERSIONS = new Set(['19.0.0', '19.1.0', '19.1.1', '19.2.0']);
const LOCKS = new Set(['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock']);
const COOLDOWN_FILES = new Set(['.npmrc', 'pnpm-workspace.yaml', '.yarnrc.yml', 'bunfig.toml']);
const THREE_DAYS_MS = 3 * 24 * 60 * 60 * 1000;
const IMPLANT_CAP = 2000;
const IMPLANT_NAMES = new Set(['setup_bun.js', 'bun_environment.js']);
const VITE_FILES = new Set(['vite.config.js', 'vite.config.ts', 'vite.config.mjs', 'vite.config.cjs', 'vite.config.mts']);
const BYPASS = /--dangerously-skip-permissions|--permission-mode(?:\s+|=)bypassPermissions|--yolo/;
const AGENT_BIN = /\b(?:claude|codex|gemini)\b/;
const SECRET_WORD = /\.env\b|\btoken\b|\bsecret\b/i;
const DAY_MS = 24 * 60 * 60 * 1000;

interface Hit {
  ruleId: string;
  title: string;
  message: string;
  file: string;
  line?: number;
  severity: Severity;
  confidence: 'high' | 'medium';
  cwe: string;
  module: ModuleName;
  remediation: string;
}

function on(flag: string): boolean {
  return process.env[flag] === '1';
}

function lineAt(text: string, index: number): number {
  return text.slice(0, Math.max(0, index)).split('\n').length;
}

function toFinding(hit: Hit): Finding {
  return {
    id: makeFindingId(hit.ruleId, hit.file, `${hit.line ?? 0}|${hit.message}`),
    ruleId: hit.ruleId,
    module: hit.module,
    title: hit.title,
    severity: hit.severity,
    confidence: hit.confidence,
    cwe: hit.cwe,
    file: hit.file,
    line: hit.line,
    message: hit.message,
    remediation: hit.remediation,
    references: [hit.cwe],
  };
}

async function readText(cwd: string, rel: string): Promise<string | undefined> {
  try {
    return await readFile(join(cwd, rel), 'utf8');
  } catch {
    return undefined;
  }
}

async function parseJs(source: string): Promise<AstNode | undefined> {
  try {
    const { parse } = await import('@typescript-eslint/typescript-estree');
    return parse(source, {
      loc: true,
      range: true,
      comment: false,
      jsx: true,
      errorOnUnknownASTType: false,
      errorOnTypeScriptSyntacticAndSemanticIssues: false,
    });
  } catch {
    return undefined;
  }
}

function rscFindings(rel: string, text: string): Finding[] {
  if (!LOCKS.has(basename(rel))) {return [];}
  const findings: Finding[] = [];
  for (const name of RSC_NAMES) {
    let from = 0;
    while (from < text.length) {
      const at = text.indexOf(name, from);
      if (at === -1) {break;}
      const window = text.slice(at + name.length, at + name.length + 48);
      const match = /[^0-9]*(\d+\.\d+\.\d+)(?![\w.-])/.exec(window);
      if (match?.[1] !== undefined && RSC_VERSIONS.has(match[1])) {
        findings.push(toFinding({
          ruleId: 'DEPS-RSC-001',
          title: 'Vulnerable React Server Components package',
          message: `${name}@${match[1]} is one of the CVE-2025-55182 versions.`,
          file: rel,
          line: lineAt(text, at),
          severity: 'critical',
          confidence: 'high',
          cwe: 'CWE-502',
          module: 'deps',
          remediation: 'Upgrade react-server-dom-webpack, react-server-dom-parcel, and react-server-dom-turbopack past the affected versions.',
        }));
      }
      from = at + name.length;
    }
  }
  return findings;
}

function durationMs(raw: string, unit: 'day' | 'minute' | 'second' | 'yarn'): number | undefined {
  if (unit === 'day') {return Number(raw) * DAY_MS;}
  if (unit === 'minute') {return Number(raw) * 60 * 1000;}
  if (unit === 'second') {return Number(raw) * 1000;}
  const match = /^(\d+)\s*([dhms])?$/.exec(raw.trim());
  if (match?.[1] === undefined) {return undefined;}
  const amount = Number(match[1]);
  const scale = match[2] === 'd' ? DAY_MS : match[2] === 'h' ? 60 * 60 * 1000 : match[2] === 'm' ? 60 * 1000 : match[2] === 's' ? 1000 : DAY_MS;
  return amount * scale;
}

function cooldownFinding(rel: string, message: string, line: number): Finding {
  return toFinding({
    ruleId: 'CONFIG-COOLDOWN-001',
    title: 'Dependency release-age gate is under three days',
    message,
    file: rel,
    line,
    severity: 'medium',
    confidence: 'medium',
    cwe: 'CWE-829',
    module: 'config',
    remediation: 'Set the package manager release-age gate to at least three days, in that tool\'s unit.',
  });
}

function gatedCooldown(rel: string, text: string, pattern: RegExp, unit: 'day' | 'minute' | 'second' | 'yarn', copy: { missing: string; short: (raw: string) => string }): Finding[] {
  const match = pattern.exec(text);
  if (match?.[1] === undefined) {return [cooldownFinding(rel, copy.missing, 1)];}
  const ms = durationMs(match[1], unit);
  if (ms !== undefined && ms < THREE_DAYS_MS) {return [cooldownFinding(rel, copy.short(match[1]), lineAt(text, match.index))];}
  return [];
}

function cooldownFindings(rel: string, text: string): Finding[] {
  const base = basename(rel);
  if (!COOLDOWN_FILES.has(base)) {return [];}
  if (base === '.npmrc') {
    return gatedCooldown(rel, text, /^\s*min-release-age\s*=\s*(\d+)/m, 'day', { missing: '.npmrc does not set min-release-age (days).', short: (raw) => `npm min-release-age is days; ${raw} is under three days.` });
  }
  if (base === 'pnpm-workspace.yaml') {
    return gatedCooldown(rel, text, /minimumReleaseAge\s*:\s*(\d+)/, 'minute', { missing: 'pnpm-workspace.yaml does not set minimumReleaseAge (minutes).', short: (raw) => `pnpm minimumReleaseAge is minutes; ${raw} is under three days.` });
  }
  if (base === '.yarnrc.yml') {
    return gatedCooldown(rel, text, /npmMinimalAgeGate\s*:\s*['"]?([^'"\n]+)/, 'yarn', { missing: '.yarnrc.yml does not set npmMinimalAgeGate.', short: (raw) => `yarn npmMinimalAgeGate ${raw.trim()} is under three days.` });
  }
  if (base !== 'bunfig.toml') {return [];}
  return gatedCooldown(rel, text, /minimumReleaseAge\s*=\s*(\d+)/, 'second', { missing: 'bunfig.toml does not set minimumReleaseAge (seconds).', short: (raw) => `bun minimumReleaseAge is seconds; ${raw} is under three days.` });
}

function versionTokens(text: string): Array<{ version: string; index: number }> {
  const out: Array<{ version: string; index: number }> = [];
  const pattern = /(?:@|"version"\s*:\s*")(\d+\.\d+\.\d+)(?![\w.-])/g;
  for (const match of text.matchAll(pattern)) {
    if (match[1] !== undefined && match.index !== undefined) {out.push({ version: match[1], index: match.index });}
  }
  return out;
}

function inflated(version: string): boolean {
  const match = /^(\d+)\.\d+\.(\d+)$/.exec(version);
  if (match?.[1] === undefined || match[2] === undefined) {return false;}
  return Number(match[1]) >= 9999 || match[2] === '999' || match[2] === '9999';
}

function inflateFindings(rel: string, text: string): Finding[] {
  if (!LOCKS.has(basename(rel))) {return [];}
  const findings: Finding[] = [];
  for (const token of versionTokens(text)) {
    if (!inflated(token.version)) {continue;}
    findings.push(toFinding({
      ruleId: 'DEPS-VERINFLATE-001',
      title: 'Inflated dependency version',
      message: `Lockfile version ${token.version} matches the flooding-dropper shape.`,
      file: rel,
      line: lineAt(text, token.index),
      severity: 'high',
      confidence: 'high',
      cwe: 'CWE-427',
      module: 'deps',
      remediation: 'Remove the dependency version whose major is 9999 or greater, or whose patch is 999 or 9999.',
    }));
  }
  return findings;
}

function implantHit(rel: string, line: number, message: string): Finding {
  return toFinding({
    ruleId: 'SUPPLY-IMPLANT-001',
    title: 'Import-time worm file',
    message,
    file: rel,
    line,
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-506',
    module: 'deps',
    remediation: 'Remove setup_bun.js and bun_environment.js, and the install script that names them.',
  });
}

function scriptImplants(rel: string, text: string): Finding[] {
  if (basename(rel) !== 'package.json') {return [];}
  let json: { scripts?: Record<string, unknown> };
  try {
    json = JSON.parse(text) as { scripts?: Record<string, unknown> };
  } catch {
    return [];
  }
  const scripts = json.scripts ?? {};
  const findings: Finding[] = [];
  for (const name of ['preinstall', 'install', 'postinstall'] as const) {
    const body = scripts[name];
    if (typeof body !== 'string') {continue;}
    if (!body.includes('setup_bun.js') && !body.includes('bun_environment.js')) {continue;}
    findings.push(implantHit(rel, 1, `${name} names setup_bun.js or bun_environment.js.`));
  }
  return findings;
}

async function implantTree(cwd: string): Promise<Finding[]> {
  const root = join(cwd, 'node_modules');
  const findings: Finding[] = [];
  const state = { n: 0 };
  async function walkDir(dir: string, rel: string): Promise<void> {
    if (state.n >= IMPLANT_CAP) {return;}
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (state.n >= IMPLANT_CAP) {return;}
      if (entry.isSymbolicLink()) {continue;}
      const child = rel === '' ? entry.name : `${rel}/${entry.name}`;
      if (entry.isFile() && IMPLANT_NAMES.has(entry.name)) {
        findings.push(implantHit(child, 1, `${entry.name} is present under node_modules.`));
      }
      if (entry.isFile() && entry.name === 'package.json') {
        state.n += 1;
        const text = await readText(cwd, child);
        if (text !== undefined) {findings.push(...scriptImplants(child, text));}
      }
      if (entry.isDirectory() && entry.name !== '.bin') {await walkDir(join(dir, entry.name), child);}
    }
  }
  await walkDir(root, 'node_modules');
  return findings;
}

function isAgentPath(rel: string): boolean {
  const base = basename(rel);
  if (base === 'AGENTS.md' || base === 'CLAUDE.md') {return true;}
  if (rel === '.github/copilot-instructions.md' || rel.endsWith('/.github/copilot-instructions.md')) {return true;}
  if (rel.includes('.cursor/rules/') || rel.includes('.windsurf/rules/')) {return true;}
  return base === 'SKILL.md' && (rel.includes('.cursor/') || rel.includes('.claude/') || rel.includes('.agents/'));
}

function agentHit(rel: string, text: string, index: number, copy: { ruleId: string; title: string; message: string; remediation: string; cwe: string }): Finding {
  return toFinding({
    ruleId: copy.ruleId,
    title: copy.title,
    message: copy.message,
    file: rel,
    line: lineAt(text, index),
    severity: 'high',
    confidence: 'high',
    cwe: copy.cwe,
    module: 'config',
    remediation: copy.remediation,
  });
}

function agentFindings(rel: string, text: string): Finding[] {
  if (!isAgentPath(rel)) {return [];}
  const findings: Finding[] = [];
  const hidden = /\u{E0001}/u.exec(text) ?? /[\u{E0001}-\u{E007F}]/u.exec(text) ?? /[\u200B\u200C\u200D\uFEFF\u2060]/.exec(text) ?? /[\u202A-\u202E\u2066-\u2069]/.exec(text);
  if (hidden?.index !== undefined) {
    findings.push(agentHit(rel, text, hidden.index, { ruleId: 'AGENT-UNICODE-001', title: 'Hidden characters in an agent instruction file', message: 'An agent instruction file contains a Unicode Tag, zero-width, or bidi character.', remediation: 'Delete the hidden characters from the instruction file.', cwe: 'CWE-74' }));
  }
  const phrase = /ignore previous|do not tell the user/i.exec(text);
  if (phrase?.index !== undefined) {
    findings.push(agentHit(rel, text, phrase.index, { ruleId: 'AGENT-INJECT-001', title: 'Instruction phrase in an agent file', message: 'An agent instruction file contains an instruction-injection phrase.', remediation: 'Remove the instruction phrase from the agent file.', cwe: 'CWE-74' }));
  }
  const url = SECRET_WORD.test(text) ? /https?:\/\//.exec(text) : null;
  if (url?.index !== undefined) {
    findings.push(agentHit(rel, text, url.index, { ruleId: 'AGENT-EXFIL-001', title: 'Agent file sends a secret to a URL', message: 'An agent instruction file names a secret and an http(s) URL.', remediation: 'Remove the instruction to send .env, a token, or a secret to a URL.', cwe: 'CWE-200' }));
  }
  const flag = AGENT_BIN.test(text) ? BYPASS.exec(text) : null;
  if (flag?.index !== undefined) {
    findings.push(agentHit(rel, text, flag.index, { ruleId: 'AGENT-SHELL-001', title: 'Agent file launches a coding agent with a permission bypass', message: 'An agent instruction file launches claude, codex, or gemini with a permission bypass.', remediation: 'Remove the permission-bypass flag from the agent instruction file.', cwe: 'CWE-74' }));
  }
  return findings;
}

interface McpTool {
  name?: unknown;
  description?: unknown;
  inputSchema?: { properties?: Record<string, { description?: unknown; default?: unknown }> };
}

function mcpTools(value: unknown): McpTool[] {
  if (value === null || typeof value !== 'object' || !('tools' in value)) {return [];}
  const tools = (value as { tools?: unknown }).tools;
  return Array.isArray(tools) ? tools.filter((tool): tool is McpTool => tool !== null && typeof tool === 'object') : [];
}

function asksForSecret(text: string): boolean {
  return /password|token|secret|api[-_ ]?key/i.test(text) && /ask|enter|provide|input|prompt/i.test(text);
}

function shellDefault(value: unknown): boolean {
  return typeof value === 'string' && (/ignore previous/i.test(value) || value.includes('`') || value.includes('$(') || value.includes('&&') || value.includes('|'));
}

function mcpDuplicate(rel: string, server: string, toolName: string, names: Map<string, string>): Finding | undefined {
  if (toolName === '') {return undefined;}
  const prior = names.get(toolName);
  if (prior === undefined) {
    names.set(toolName, server);
    return undefined;
  }
  if (prior === server) {return undefined;}
  return toFinding({
    ruleId: 'MCP-008',
    title: 'MCP tool name declared by two servers',
    message: `Tool ${toolName} is declared by ${prior} and ${server}.`,
    file: rel,
    line: 1,
    severity: 'medium',
    confidence: 'medium',
    cwe: 'CWE-290',
    module: 'config',
    remediation: 'Give each server its own tool names.',
  });
}

function mcpSecret(rel: string, server: string, tool: McpTool): Finding | undefined {
  const description = typeof tool.description === 'string' ? tool.description : '';
  const props = tool.inputSchema?.properties ?? {};
  const secretKey = Object.keys(props).some((key) => /password|token|secret|api[-_]?key/i.test(key));
  const secretText = asksForSecret(description) || Object.values(props).some((prop) => typeof prop.description === 'string' && asksForSecret(prop.description));
  if (!secretKey && !secretText) {return undefined;}
  return toFinding({
    ruleId: 'MCP-006',
    title: 'MCP tool asks for a secret',
    message: `Server ${server} asks for a password, token, secret, or API key.`,
    file: rel,
    line: 1,
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-74',
    module: 'config',
    remediation: 'Do not ask the user for a secret in an MCP tool schema or description.',
  });
}

function mcpShells(rel: string, server: string, tool: McpTool): Finding[] {
  const props = tool.inputSchema?.properties ?? {};
  const findings: Finding[] = [];
  for (const prop of Object.values(props)) {
    if (!shellDefault(prop.default)) {continue;}
    findings.push(toFinding({
      ruleId: 'MCP-007',
      title: 'MCP schema default is a shell or instruction',
      message: `Server ${server} has a schema default that is a shell command or an instruction phrase.`,
      file: rel,
      line: 1,
      severity: 'high',
      confidence: 'high',
      cwe: 'CWE-74',
      module: 'config',
      remediation: 'Remove the shell command or instruction phrase from the schema default.',
    }));
  }
  return findings;
}

function mcpFindings(rel: string, text: string): Finding[] {
  if (!text.includes('mcpServers')) {return [];}
  let json: { mcpServers?: Record<string, unknown> };
  try {
    json = JSON.parse(text) as { mcpServers?: Record<string, unknown> };
  } catch {
    return [];
  }
  const servers = json.mcpServers;
  if (servers === undefined) {return [];}
  const findings: Finding[] = [];
  const names = new Map<string, string>();
  for (const [server, body] of Object.entries(servers)) {
    for (const tool of mcpTools(body)) {
      const toolName = typeof tool.name === 'string' ? tool.name : '';
      const duplicate = mcpDuplicate(rel, server, toolName, names);
      if (duplicate !== undefined) {findings.push(duplicate);}
      const secret = mcpSecret(rel, server, tool);
      if (secret !== undefined) {findings.push(secret);}
      findings.push(...mcpShells(rel, server, tool));
    }
  }
  return findings;
}

function propKey(node: AstNode): string | undefined {
  if (node.type !== 'Property') {return undefined;}
  return node.key.type === 'Identifier' ? node.key.name : literalString(node.key);
}

function parentOf(node: AstNode): AstNode | undefined {
  return (node as { parent?: AstNode }).parent;
}

function underServerFs(node: AstNode): boolean {
  const fsProp = parentOf(node) !== undefined ? parentOf(parentOf(node) as AstNode) : undefined;
  if (fsProp?.type !== 'Property' || propKey(fsProp) !== 'fs') {return false;}
  const serverProp = parentOf(parentOf(fsProp) as AstNode);
  return serverProp?.type === 'Property' && propKey(serverProp) === 'server';
}

function rootAllow(value: string): boolean {
  return value === '/' || /^[A-Za-z]:\\?$/.test(value) || /^[A-Za-z]:\/$/.test(value);
}

function viteFindings(rel: string, ast: AstNode): Finding[] {
  if (!VITE_FILES.has(basename(rel))) {return [];}
  attachParents(ast);
  let hit = false;
  walk(ast, (node) => {
    if (node.type !== 'Property' || !underServerFs(node)) {return;}
    const key = propKey(node);
    if (key === 'strict' && node.value.type === 'Literal' && node.value.value === false) {hit = true;}
    if (key === 'allow' && node.value.type === 'ArrayExpression') {
      for (const el of node.value.elements) {
        const text = el !== null && el.type !== 'SpreadElement' ? literalString(el) : undefined;
        if (text !== undefined && rootAllow(text)) {hit = true;}
      }
    }
  });
  if (!hit) {return [];}
  return [toFinding({
    ruleId: 'CONFIG-VITEFS-001',
    title: 'Vite dev server can read the filesystem root',
    message: 'server.fs.strict is false, or server.fs.allow includes a filesystem root.',
    file: rel,
    line: 1,
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-22',
    module: 'config',
    remediation: 'Leave server.fs.strict at its default and do not allow the filesystem root.',
  })];
}

function isHost(node: AstNode): boolean {
  if (node.type === 'CallExpression' && calleeName(node) === 'get') {
    const arg = literalString(node.arguments[0]);
    return arg === 'host' || arg === 'x-forwarded-host';
  }
  if (node.type !== 'MemberExpression') {return false;}
  const name = propName(node) ?? (node.property.type === 'Literal' ? literalString(node.property) : undefined);
  if (name !== 'host' && name !== 'x-forwarded-host') {return false;}
  return node.object.type === 'MemberExpression' && propName(node.object) === 'headers';
}

function hostNames(ast: AstNode): Set<string> {
  const names = new Set<string>();
  walk(ast, (node) => {
    if (node.type !== 'VariableDeclarator' || node.id.type !== 'Identifier' || node.init === null || node.init === undefined) {return;}
    if (isHost(node.init)) {names.add(node.id.name);}
  });
  return names;
}

function usesHost(node: AstNode, names: ReadonlySet<string>): boolean {
  if (isHost(node)) {return true;}
  return node.type === 'Identifier' && names.has(node.name);
}

function hasHttp(node: AstNode): boolean {
  const text = literalString(node);
  if (text !== undefined && (text.includes('://') || text.includes('http'))) {return true;}
  if (node.type === 'TemplateLiteral') {
    return node.quasis.some((quasi) => quasi.value.cooked?.includes('://') === true || quasi.value.cooked?.includes('http') === true);
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {return hasHttp(node.left) || hasHttp(node.right);}
  return false;
}

function hasHost(node: AstNode, names: ReadonlySet<string>): boolean {
  if (usesHost(node, names)) {return true;}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => hasHost(expr, names));}
  if (node.type === 'BinaryExpression' && node.operator === '+') {return hasHost(node.left, names) || hasHost(node.right, names);}
  return false;
}

function absoluteUrl(node: AstNode, names: ReadonlySet<string>): boolean {
  return hasHttp(node) && hasHost(node, names);
}

function isLocation(node: AstNode): boolean {
  if (node.type !== 'CallExpression' && node.type !== 'NewExpression') {return false;}
  const name = calleeName(node);
  if (name === 'redirect' || name === 'location' || name === 'sendMail') {return true;}
  if (name !== 'setHeader' && name !== 'set') {return false;}
  return literalString(node.arguments[0])?.toLowerCase() === 'location';
}

function hostFindings(rel: string, ast: AstNode): Finding[] {
  const names = hostNames(ast);
  const urls = new Set<string>();
  walk(ast, (node) => {
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init !== null && node.init !== undefined && absoluteUrl(node.init, names)) {
      urls.add(node.id.name);
    }
  });
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (node.type !== 'CallExpression' || !isLocation(node)) {return;}
    const taintedUrl = node.arguments.some((arg) => {
      if (arg.type === 'SpreadElement') {return false;}
      if (absoluteUrl(arg, names)) {return true;}
      if (arg.type === 'Identifier' && urls.has(arg.name)) {return true;}
      if (arg.type === 'ObjectExpression') {
        return arg.properties.some((prop) => prop.type === 'Property' && (absoluteUrl(prop.value, names) || (prop.value.type === 'Identifier' && urls.has(prop.value.name))));
      }
      return false;
    });
    if (!taintedUrl) {return;}
    findings.push(toFinding({
      ruleId: 'SAST-HOST-001',
      title: 'Host header copied into an absolute URL',
      message: 'Host or X-Forwarded-Host is copied into an absolute URL passed to a redirect or a mailer.',
      file: rel,
      line: node.loc?.start.line,
      severity: 'high',
      confidence: 'high',
      cwe: 'CWE-644',
      module: 'sast',
      remediation: 'Build the public URL from a configured host, not from the Host header.',
    }));
  });
  return findings;
}

function htmlTrue(node: AstNode): boolean {
  if (node.type !== 'ObjectExpression') {return false;}
  return node.properties.some((prop) => {
    if (prop.type !== 'Property') {return false;}
    const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
    return key === 'html' && prop.value.type === 'Literal' && prop.value.value === true;
  });
}

function fileHasHtmlTrue(ast: AstNode): boolean {
  let hit = false;
  walk(ast, (node) => {
    if ((node.type === 'CallExpression' || node.type === 'NewExpression') && node.arguments.some((arg) => arg.type !== 'SpreadElement' && htmlTrue(arg))) {
      hit = true;
    }
  });
  return hit;
}

function isMarkedCall(node: AstNode): boolean {
  if (node.type !== 'CallExpression') {return false;}
  if (calleeName(node) === 'marked' && node.callee.type === 'Identifier') {return true;}
  if (calleeName(node) !== 'parse' || node.callee.type !== 'MemberExpression') {return false;}
  const object = node.callee.object;
  return object.type === 'Identifier' && object.name === 'marked';
}

function markupFindings(rel: string, source: string, ast: AstNode): Finding[] {
  const markdown = /['"]markdown-it['"]/.test(source);
  const marked = /['"]marked['"]/.test(source);
  if (!markdown && !marked) {return [];}
  const facts = analyzeFile(ast);
  const html = markdown && fileHasHtmlTrue(ast);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (node.type !== 'CallExpression') {return;}
    const arg = node.arguments[0];
    if (arg === undefined || arg.type === 'SpreadElement' || !nodeIsTainted(arg, facts)) {return;}
    const markedCall = marked && isMarkedCall(node);
    const renderCall = html && calleeName(node) === 'render';
    if (!markedCall && !renderCall) {return;}
    findings.push(toFinding({
      ruleId: 'SAST-MARKUP-001',
      title: 'Request data is rendered as markdown HTML',
      message: 'Request data reaches markdown-it with html: true, or marked.',
      file: rel,
      line: node.loc?.start.line,
      severity: 'high',
      confidence: 'high',
      cwe: 'CWE-79',
      module: 'sast',
      remediation: 'Do not render request markdown with HTML enabled.',
    }));
  });
  return findings;
}

function trustFindings(rel: string, source: string, ast: AstNode): Finding[] {
  if (!/next-auth|@auth\/|NextAuth/.test(source)) {return [];}
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (node.type !== 'Property') {return;}
    const key = propKey(node);
    if (key !== 'trustHost' || node.value.type !== 'Literal' || node.value.value !== true) {return;}
    findings.push(toFinding({
      ruleId: 'SAST-TRUSTHOST-001',
      title: 'Auth.js trustHost is true',
      message: 'NextAuth or Auth.js sets trustHost to true.',
      file: rel,
      line: node.loc?.start.line,
      severity: 'medium',
      confidence: 'medium',
      cwe: 'CWE-346',
      module: 'sast',
      remediation: 'Set trustHost to false, or omit it, unless the host is fixed outside the request.',
    }));
  });
  return findings;
}

function callText(source: string, node: AstNode): string {
  if (node.range === undefined) {return '';}
  return source.slice(node.range[0], node.range[1]);
}

function spawnFindings(rel: string, source: string, ast: AstNode): Finding[] {
  const findings: Finding[] = [];
  walk(ast, (node) => {
    const call = node.type === 'CallExpression' || node.type === 'NewExpression';
    if (!call) {return;}
    const name = calleeName(node);
    const deno = node.type === 'NewExpression' && node.callee.type === 'MemberExpression' && propName(node.callee) === 'Command';
    const spawn = name === 'exec' || name === 'execSync' || name === 'spawn' || name === 'spawnSync' || deno;
    if (!spawn) {return;}
    const text = callText(source, node);
    if (!AGENT_BIN.test(text) || !BYPASS.test(text)) {return;}
    findings.push(toFinding({
      ruleId: 'SAST-AGENTSPAWN-001',
      title: 'Coding agent launched with a permission bypass',
      message: 'claude, codex, or gemini is launched with a permission-bypass flag.',
      file: rel,
      line: node.loc?.start.line,
      severity: 'high',
      confidence: 'high',
      cwe: 'CWE-78',
      module: 'sast',
      remediation: 'Launch the coding agent without a permission-bypass flag.',
    }));
  });
  return findings;
}

function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort((a, b) => `${a.ruleId}|${a.file ?? ''}|${a.line ?? 0}|${a.message}`.localeCompare(`${b.ruleId}|${b.file ?? ''}|${b.line ?? 0}|${b.message}`));
}

function textFindings(rel: string, text: string): Finding[] {
  const findings: Finding[] = [];
  if (on('FULLSHIELD_EXPERIMENTAL_RSC')) {findings.push(...rscFindings(rel, text));}
  if (on('FULLSHIELD_EXPERIMENTAL_COOLDOWN')) {findings.push(...cooldownFindings(rel, text));}
  if (on('FULLSHIELD_EXPERIMENTAL_VERINFLATE')) {findings.push(...inflateFindings(rel, text));}
  if (on('FULLSHIELD_EXPERIMENTAL_IMPORTIMPLANT') && IMPLANT_NAMES.has(basename(rel))) {
    findings.push(implantHit(rel, 1, `${basename(rel)} is in the project.`));
  }
  if (on('FULLSHIELD_EXPERIMENTAL_IMPORTIMPLANT')) {findings.push(...scriptImplants(rel, text));}
  if (on('FULLSHIELD_EXPERIMENTAL_AGENTRULES')) {findings.push(...agentFindings(rel, text));}
  if (on('FULLSHIELD_EXPERIMENTAL_MCPPOISON')) {findings.push(...mcpFindings(rel, text));}
  return findings;
}

function astFindings(rel: string, text: string, ast: AstNode): Finding[] {
  const findings: Finding[] = [];
  if (on('FULLSHIELD_EXPERIMENTAL_VITEFS')) {findings.push(...viteFindings(rel, ast));}
  if (on('FULLSHIELD_EXPERIMENTAL_HOSTPOISON')) {findings.push(...hostFindings(rel, ast));}
  if (on('FULLSHIELD_EXPERIMENTAL_MARKUP')) {findings.push(...markupFindings(rel, text, ast));}
  if (on('FULLSHIELD_EXPERIMENTAL_TRUSTHOST')) {findings.push(...trustFindings(rel, text, ast));}
  if (on('FULLSHIELD_EXPERIMENTAL_AGENTSPAWN')) {findings.push(...spawnFindings(rel, text, ast));}
  return findings;
}

/** Experimental 1.6.0 checks. The caller loads this module only when a flag is 1. */
export async function marketFindings(cwd: string, files: readonly string[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  const js: Array<{ rel: string; text: string; ast: AstNode }> = [];
  for (const rel of files) {
    const text = await readText(cwd, rel);
    if (text === undefined) {continue;}
    findings.push(...textFindings(rel, text));
    if (!/\.[cm]?[jt]sx?$/.test(rel)) {continue;}
    const ast = await parseJs(text);
    if (ast === undefined) {continue;}
    js.push({ rel, text, ast });
  }
  if (on('FULLSHIELD_EXPERIMENTAL_IMPORTIMPLANT')) {findings.push(...(await implantTree(cwd)));}
  for (const file of js) {findings.push(...astFindings(file.rel, file.text, file.ast));}
  return sortFindings(findings);
}
