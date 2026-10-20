import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Severity } from '../../core/finding.js';
import { makeFindingId, sortFindings, type Finding } from '../../core/finding.js';
import { packageVersion } from '../../core/version.js';
import { parseLockfile } from '../deps/lockfile.js';
import { rangeSatisfies } from '../deps/semver.js';
import {
  attachParents,
  boundNames,
  calleeName,
  isFunctionNode,
  literalString,
  propName,
  walk,
} from './ast.js';
import type { AstNode } from './types.js';

const KINDS = new Set(['source', 'sink', 'sanitizer', 'validator']);
const CLASSES = new Set([
  'sqli',
  'nosqli',
  'cmdi',
  'path',
  'xss',
  'ssrf',
  'redirect',
  'eval',
  'jwt',
  'crypto',
  'proto',
]);
const BUILTINS = new Set(['child_process', 'fs', 'path']);
const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'];
const LOCATION = new Set(['body', 'query', 'param', 'params', 'check', 'checkBody', 'checkQuery', 'header']);
const ROUTE_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all', 'use']);

const RULES: Record<string, { id: string; title: string; severity: Severity; cwe: string }> = {
  sqli: { id: 'SAST-SQLI-001', title: 'SQL injection via string concatenation', severity: 'high', cwe: 'CWE-89' },
  nosqli: { id: 'SAST-NOSQLI-001', title: 'NoSQL injection via raw request object filter', severity: 'high', cwe: 'CWE-943' },
  cmdi: { id: 'SAST-CMDI-001', title: 'Command injection via shell execution', severity: 'high', cwe: 'CWE-78' },
  path: { id: 'SAST-PATH-001', title: 'Path traversal via unsanitized file path', severity: 'high', cwe: 'CWE-22' },
  xss: { id: 'SAST-XSS-001', title: 'Reflected XSS via HTML response', severity: 'high', cwe: 'CWE-79' },
  ssrf: { id: 'SAST-SSRF-001', title: 'SSRF via tainted URL', severity: 'high', cwe: 'CWE-918' },
  redirect: { id: 'SAST-REDIRECT-001', title: 'Open redirect', severity: 'high', cwe: 'CWE-601' },
  eval: { id: 'SAST-EVAL-001', title: 'Dynamic code execution with a non-literal', severity: 'high', cwe: 'CWE-95' },
  jwt: { id: 'SAST-JWT-001', title: 'Insecure JWT verification', severity: 'high', cwe: 'CWE-347' },
  crypto: { id: 'SAST-CRYPTO-001', title: 'Weak cryptography for secrets or tokens', severity: 'medium', cwe: 'CWE-327' },
  proto: { id: 'SAST-PROTO-001', title: 'Prototype pollution', severity: 'high', cwe: 'CWE-1321' },
};

const RULE_CLASS = new Map(Object.entries(RULES).map(([sinkClass, rule]) => [rule.id, sinkClass]));

export interface ModelEntry {
  package: string;
  versionRange: string;
  kind: 'source' | 'sink' | 'sanitizer' | 'validator';
  sinkClass: string;
  memberPath: string;
  argumentIndex: number;
  reference: string;
}

interface ModelCatalog {
  fullshieldVersion: string;
  entries: ModelEntry[];
}

interface ClearMark {
  line: number;
  sinkClass: string;
  packageName: string;
  field?: string;
  name?: string;
}

let activeSources: ModelEntry[] = [];
let activeSinks: ModelEntry[] = [];

export function setActiveModels(entries: readonly ModelEntry[] | undefined): void {
  activeSources = [];
  activeSinks = [];
  if (entries === undefined) return;
  for (const entry of entries) {
    if (entry.kind === 'source') activeSources.push(entry);
    else if (entry.kind === 'sink') activeSinks.push(entry);
  }
}

export function versionInRange(range: string, version: string): boolean {
  const orParts = range.split('||').map((part) => part.trim()).filter((part) => part.length > 0);
  if (orParts.length === 0) return false;
  return orParts.some((part) => {
    const atoms = part.split(/\s+/).filter((atom) => atom.length > 0);
    return atoms.length > 0 && atoms.every((atom) => rangeSatisfies(atom, version) === true);
  });
}

function catalogPath(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 6; depth += 1) {
    const candidate = join(dir, 'models', 'index.json');
    try {
      readFileSync(candidate, 'utf8');
      return candidate;
    } catch {
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  throw new Error('models/index.json not found');
}

function asEntry(value: unknown): ModelEntry {
  if (typeof value !== 'object' || value === null) throw new Error('model entry must be an object');
  const row = value as Record<string, unknown>;
  if (typeof row.package !== 'string' || row.package.length === 0) throw new Error('model entry package');
  if (typeof row.versionRange !== 'string' || row.versionRange.length === 0) throw new Error('model entry versionRange');
  if (typeof row.kind !== 'string' || !KINDS.has(row.kind)) throw new Error('model entry kind');
  if (typeof row.sinkClass !== 'string' || !CLASSES.has(row.sinkClass)) throw new Error('model entry sinkClass');
  if (typeof row.memberPath !== 'string' || row.memberPath.length === 0 || /\s/.test(row.memberPath)) {
    throw new Error('model entry memberPath');
  }
  if (typeof row.argumentIndex !== 'number' || !Number.isInteger(row.argumentIndex) || row.argumentIndex < 0) {
    throw new Error('model entry argumentIndex');
  }
  if (typeof row.reference !== 'string' || !/^https?:\/\/\S+$/.test(row.reference)) throw new Error('model entry reference');
  return {
    package: row.package,
    versionRange: row.versionRange,
    kind: row.kind as ModelEntry['kind'],
    sinkClass: row.sinkClass,
    memberPath: row.memberPath,
    argumentIndex: row.argumentIndex,
    reference: row.reference,
  };
}

export function loadModelCatalog(): ModelCatalog {
  const raw = JSON.parse(readFileSync(catalogPath(), 'utf8')) as { fullshieldVersion?: unknown; entries?: unknown };
  if (raw.fullshieldVersion !== packageVersion()) {
    throw new Error('model pack version does not match FullShield');
  }
  if (!Array.isArray(raw.entries)) throw new Error('model entries must be an array');
  return { fullshieldVersion: raw.fullshieldVersion, entries: raw.entries.map(asEntry) };
}

function addVersion(map: Map<string, string[]>, name: string, version: string): void {
  if (!/^\d+\.\d+\.\d+/.test(version)) return;
  const list = map.get(name) ?? [];
  if (!list.includes(version)) list.push(version);
  map.set(name, list);
}

function installedVersions(cwd: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const filename of LOCKFILES) {
    let text: string;
    try {
      text = readFileSync(join(cwd, filename), 'utf8');
    } catch {
      continue;
    }
    try {
      for (const pkg of parseLockfile(filename, text)) addVersion(map, pkg.name, pkg.version);
    } catch {
      // Unreadable lockfile; other sources still apply.
    }
  }
  try {
    const pkg = JSON.parse(readFileSync(join(cwd, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, unknown>;
      devDependencies?: Record<string, unknown>;
      optionalDependencies?: Record<string, unknown>;
    };
    for (const field of [pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies]) {
      if (field === undefined) continue;
      for (const [name, version] of Object.entries(field)) {
        if (typeof version === 'string') addVersion(map, name, version);
      }
    }
  } catch {
    // No manifest.
  }
  for (const name of BUILTINS) {
    if (!map.has(name)) addVersion(map, name, process.versions.node);
  }
  return map;
}

export function resolveModelPacks(cwd: string): { active: ModelEntry[]; info: string[] } {
  const catalog = loadModelCatalog();
  const installed = installedVersions(cwd);
  const grouped = new Map<string, ModelEntry[]>();
  for (const entry of catalog.entries) {
    const list = grouped.get(entry.package) ?? [];
    list.push(entry);
    grouped.set(entry.package, list);
  }
  const active: ModelEntry[] = [];
  const info: string[] = [];
  for (const [name, entries] of grouped) {
    const versions = installed.get(name);
    if (versions === undefined || versions.length === 0) continue;
    const matched = entries.filter((entry) => versions.some((version) => versionInRange(entry.versionRange, version)));
    if (matched.length > 0) {
      active.push(...matched);
      continue;
    }
    const version = versions[0] ?? '';
    const range = entries[0]?.versionRange ?? '';
    info.push(`model pack ${name} skipped: ${version} is outside ${range}`);
  }
  return { active, info };
}

function segmentsOf(memberPath: string): string[] {
  return memberPath.split('.').map((part) => part.replace(/\(\)$/g, '')).filter((part) => part.length > 0);
}

function chainOf(node: AstNode): string[] {
  const names: string[] = [];
  let current: AstNode | undefined = node;
  while (current !== undefined) {
    if (current.type === 'CallExpression') {
      const name = calleeName(current);
      if (name !== undefined) names.push(name);
      if (current.callee.type === 'MemberExpression') {
        current = current.callee.object;
        continue;
      }
      break;
    }
    if (current.type === 'MemberExpression') {
      const name = propName(current);
      if (name !== undefined) names.push(name);
      current = current.object;
      continue;
    }
    if (current.type === 'Identifier') {
      names.push(current.name);
      break;
    }
    break;
  }
  return names.reverse();
}

function chainHas(memberPath: string, node: AstNode): boolean {
  const want = segmentsOf(memberPath);
  const got = chainOf(node);
  if (want.length === 0 || got.length === 0 || got[got.length - 1] !== want[want.length - 1]) return false;
  let index = 0;
  for (const name of got) {
    if (name === want[index]) index += 1;
    if (index === want.length) return true;
  }
  return false;
}

export function modelSourceNode(node: AstNode): boolean {
  if (activeSources.length === 0) return false;
  if (node.type !== 'CallExpression' && node.type !== 'MemberExpression') return false;
  return activeSources.some((entry) => chainHas(entry.memberPath, node));
}

function jwtAllowsAlgorithms(call: AstNode): boolean {
  if (call.type !== 'CallExpression') return false;
  const opts = call.arguments[2];
  if (opts === undefined || opts.type !== 'ObjectExpression') return false;
  for (const prop of opts.properties) {
    if (prop.type !== 'Property') continue;
    const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
    if (key !== 'algorithms' || prop.value.type !== 'ArrayExpression') continue;
    const values: unknown[] = [];
    for (const el of prop.value.elements) {
      if (el !== null && el.type === 'Literal') values.push(el.value);
    }
    return values.length > 0 && !values.some((value) => value === 'none' || value === 'None');
  }
  return false;
}

function sourceImports(source: string, packageName: string): boolean {
  const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?:require\\(\\s*|from\\s+|import\\(\\s*)['"]${escaped}['"]`).test(source);
}

function snippetOf(source: string, node: AstNode): string {
  if (node.range === undefined) return '';
  return source.slice(node.range[0], node.range[1]).replace(/\s+/g, ' ').trim().slice(0, 120);
}

export function modelSinkFindings(
  filename: string,
  source: string,
  ast: AstNode,
  isTainted: (node: AstNode) => boolean,
  existing: readonly Finding[],
): Finding[] {
  if (activeSinks.length === 0) return [];
  const out: Finding[] = [];
  walk(ast, (node) => {
    if (node.type !== 'CallExpression') return;
    for (const entry of activeSinks) {
      if (!sourceImports(source, entry.package) || !chainHas(entry.memberPath, node)) continue;
      if (entry.sinkClass === 'jwt' && jwtAllowsAlgorithms(node)) continue;
      const arg = node.arguments[entry.argumentIndex];
      if (arg === undefined || arg.type === 'SpreadElement' || !isTainted(arg)) continue;
      const rule = RULES[entry.sinkClass];
      if (rule === undefined) continue;
      const line = node.loc?.start.line ?? 0;
      if (existing.some((finding) => finding.ruleId === rule.id && finding.line === line)) continue;
      if (out.some((finding) => finding.ruleId === rule.id && finding.line === line)) continue;
      const snippet = snippetOf(source, node);
      out.push({
        id: makeFindingId(rule.id, filename, `${line}|${snippet}`),
        ruleId: rule.id,
        module: 'sast',
        title: rule.title,
        severity: rule.severity,
        confidence: 'high',
        cwe: rule.cwe,
        file: filename,
        line,
        column: node.loc?.start.column,
        snippet,
        message: `Tainted input reaches ${entry.package} ${entry.memberPath}.`,
        remediation: `${rule.title}. See ${entry.reference}`,
        references: [entry.reference],
      });
    }
  });
  return out;
}

function parentOf(node: AstNode): AstNode | undefined {
  return (node as { parent?: AstNode }).parent;
}

function bagsFor(factory: string): string[] {
  if (factory === 'body' || factory === 'checkBody') return ['body'];
  if (factory === 'query' || factory === 'checkQuery') return ['query'];
  if (factory === 'param' || factory === 'params') return ['params'];
  if (factory === 'check') return ['body', 'query', 'params'];
  if (factory === 'header') return ['headers'];
  return [];
}

function requestField(node: AstNode): { bag: string; field?: string } | undefined {
  if (node.type !== 'MemberExpression' || node.computed === true) return undefined;
  const prop = propName(node);
  if (prop === undefined) return undefined;
  if (node.object.type === 'Identifier' && node.object.name === 'req') {
    if (prop === 'body' || prop === 'query' || prop === 'params' || prop === 'headers') return { bag: prop };
    return undefined;
  }
  if (node.object.type === 'MemberExpression') {
    const inner = requestField(node.object);
    if (inner?.field === undefined && inner !== undefined) return { bag: inner.bag, field: prop };
  }
  return undefined;
}

function literalFields(node: AstNode | undefined): string[] {
  if (node === undefined || node.type === 'SpreadElement') return [];
  const one = literalString(node);
  if (one !== undefined) return [one];
  if (node.type === 'ArrayExpression') {
    return node.elements.flatMap((el) => literalFields(el ?? undefined));
  }
  return [];
}

function factoryCall(node: AstNode, factory: string): AstNode | undefined {
  let current: AstNode | undefined = node;
  while (current !== undefined) {
    if (current.type === 'CallExpression' && calleeName(current) === factory) return current;
    if (current.type === 'CallExpression' && current.callee.type === 'MemberExpression') {
      current = current.callee.object;
      continue;
    }
    if (current.type === 'MemberExpression') {
      current = current.object;
      continue;
    }
    break;
  }
  return undefined;
}

function assignedNames(node: AstNode): string[] {
  let parent = parentOf(node);
  if (parent?.type === 'AwaitExpression') parent = parentOf(parent);
  if (parent?.type === 'VariableDeclarator') return boundNames(parent.id);
  if (parent?.type === 'AssignmentExpression') return boundNames(parent.left);
  return [];
}

function marksFrom(entry: ModelEntry, call: AstNode, line: number): ClearMark[] {
  if (call.type !== 'CallExpression' || !chainHas(entry.memberPath, call)) return [];
  const factory = segmentsOf(entry.memberPath).find((segment) => LOCATION.has(segment));
  if (factory !== undefined) {
    const found = factoryCall(call, factory);
    const arg = found?.type === 'CallExpression' ? found.arguments[entry.argumentIndex] : undefined;
    const bags = bagsFor(factory);
    return literalFields(arg).flatMap((field) =>
      bags.map((bag) => ({
        line,
        sinkClass: entry.sinkClass,
        packageName: entry.package,
        field: `${bag}:${field}`,
      })),
    );
  }
  if (entry.kind === 'sanitizer') {
    return assignedNames(call).map((name) => ({
      line,
      sinkClass: entry.sinkClass,
      packageName: entry.package,
      name,
    }));
  }
  const arg = call.arguments[entry.argumentIndex];
  if (arg === undefined || arg.type === 'SpreadElement') return [];
  const field = requestField(arg);
  if (field?.field !== undefined) {
    return [{ line, sinkClass: entry.sinkClass, packageName: entry.package, field: `${field.bag}:${field.field}` }];
  }
  if (arg.type === 'Identifier') {
    return [{ line, sinkClass: entry.sinkClass, packageName: entry.package, name: arg.name }];
  }
  return [];
}

function isRouteCall(node: AstNode): boolean {
  return (
    node.type === 'CallExpression' &&
    node.callee.type === 'MemberExpression' &&
    ROUTE_METHODS.has(propName(node.callee) ?? '')
  );
}

function namedFunctions(ast: AstNode): Map<string, AstNode> {
  const map = new Map<string, AstNode>();
  walk(ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id !== null) map.set(node.id.name, node);
    if (
      node.type === 'VariableDeclarator' &&
      node.id.type === 'Identifier' &&
      node.init !== null &&
      node.init !== undefined &&
      isFunctionNode(node.init)
    ) {
      map.set(node.id.name, node.init);
    }
  });
  return map;
}

function handlersOf(node: AstNode, named: Map<string, AstNode>): AstNode[] {
  if (isFunctionNode(node)) return [node];
  if (node.type === 'Identifier') {
    const found = named.get(node.name);
    return found === undefined ? [] : [found];
  }
  if (node.type === 'ArrayExpression') {
    return node.elements.flatMap((el) => (el === null || el.type === 'SpreadElement' ? [] : handlersOf(el, named)));
  }
  return [];
}

function callsOf(node: AstNode): AstNode[] {
  if (node.type === 'CallExpression') return [node];
  if (node.type === 'ArrayExpression') {
    return node.elements.flatMap((el) => (el === null || el.type === 'SpreadElement' ? [] : callsOf(el)));
  }
  return [];
}

function walkFunction(fn: AstNode, visit: (node: AstNode) => void): void {
  function inner(node: AstNode): void {
    if (node !== fn && isFunctionNode(node)) return;
    visit(node);
    for (const key of Object.keys(node) as Array<keyof AstNode>) {
      if (key === 'loc' || key === 'range' || key === 'type' || key === 'parent') continue;
      const value = node[key] as unknown;
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child !== null && typeof child === 'object' && 'type' in child) inner(child as AstNode);
        }
      } else if (value !== null && typeof value === 'object' && 'type' in value) {
        inner(value as AstNode);
      }
    }
  }
  inner(fn);
}

function enclosingFunction(node: AstNode): AstNode | undefined {
  let current = parentOf(node);
  while (current !== undefined) {
    if (isFunctionNode(current)) return current;
    current = parentOf(current);
  }
  return undefined;
}

interface Cover {
  blocked: boolean;
  packageName?: string;
}

function mergeCover(parts: Cover[]): Cover {
  return {
    blocked: parts.some((part) => part.blocked),
    packageName: parts.find((part) => part.packageName !== undefined)?.packageName,
  };
}

function coverNode(node: AstNode, sinkClass: string, marks: readonly ClearMark[], aliases: ReadonlyMap<string, string>, clearers: readonly ModelEntry[]): Cover {
  if (node.type === 'Literal') return { blocked: false };
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return { blocked: false };
  if (node.type === 'CallExpression') {
    const match = clearers.find((entry) => entry.sinkClass === sinkClass && chainHas(entry.memberPath, node));
    if (match !== undefined) return { blocked: false, packageName: match.package };
  }
  const field = requestField(node);
  if (field?.field !== undefined) {
    const key = `${field.bag}:${field.field}`;
    const hit = marks.find((mark) => mark.field === key);
    return hit === undefined ? { blocked: true } : { blocked: false, packageName: hit.packageName };
  }
  if (field !== undefined) return { blocked: true };
  if (node.type === 'Identifier') {
    const named = marks.find((mark) => mark.name === node.name);
    if (named !== undefined) return { blocked: false, packageName: named.packageName };
    const alias = aliases.get(node.name);
    if (alias !== undefined) {
      const hit = marks.find((mark) => mark.field === alias);
      return hit === undefined ? { blocked: true } : { blocked: false, packageName: hit.packageName };
    }
    return { blocked: true };
  }
  if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression') {
    return mergeCover([coverNode(node.left, sinkClass, marks, aliases, clearers), coverNode(node.right, sinkClass, marks, aliases, clearers)]);
  }
  if (node.type === 'TemplateLiteral') {
    return mergeCover(node.expressions.map((expr) => coverNode(expr, sinkClass, marks, aliases, clearers)));
  }
  if (node.type === 'AwaitExpression') return coverNode(node.argument, sinkClass, marks, aliases, clearers);
  if (node.type === 'ObjectExpression') {
    const parts: Cover[] = [];
    for (const prop of node.properties) {
      if (prop.type === 'Property') parts.push(coverNode(prop.value, sinkClass, marks, aliases, clearers));
      if (prop.type === 'SpreadElement') parts.push(coverNode(prop.argument, sinkClass, marks, aliases, clearers));
    }
    return parts.length === 0 ? { blocked: false } : mergeCover(parts);
  }
  if (node.type === 'CallExpression') {
    const args = node.arguments.filter((arg) => arg.type !== 'SpreadElement');
    return args.length === 0 ? { blocked: true } : mergeCover(args.map((arg) => coverNode(arg, sinkClass, marks, aliases, clearers)));
  }
  return { blocked: true };
}

function aliasesBefore(fn: AstNode, line: number): Map<string, string> {
  const aliases = new Map<string, string>();
  walkFunction(fn, (node) => {
    const binding = aliasBinding(node);
    if (binding === undefined) return;
    const at = node.loc?.start.line ?? 0;
    if (at >= line) return;
    const field = requestField(binding.init);
    if (field?.field === undefined) return;
    for (const name of binding.names) aliases.set(name, `${field.bag}:${field.field}`);
  });
  return aliases;
}

/** Only a declarator or an assignment has a left-hand name. Other statements are skipped. */
function aliasBinding(node: AstNode): { init: AstNode; names: string[] } | undefined {
  if (node.type === 'VariableDeclarator') {
    if (node.init === undefined || node.init === null) return undefined;
    return { init: node.init, names: boundNames(node.id) };
  }
  if (node.type === 'AssignmentExpression') {
    return { init: node.right, names: boundNames(node.left) };
  }
  return undefined;
}

function marksBefore(fn: AstNode, line: number, clearers: readonly ModelEntry[], route: readonly ClearMark[]): ClearMark[] {
  const marks = route.filter((mark) => mark.line < line);
  walkFunction(fn, (node) => {
    if (node.type !== 'CallExpression') return;
    const at = node.loc?.start.line ?? 0;
    if (at >= line) return;
    for (const entry of clearers) marks.push(...marksFrom(entry, node, at));
  });
  return marks.filter((mark) => mark.line < line);
}

async function parseCode(source: string): Promise<AstNode | undefined> {
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

function sinkCall(ast: AstNode, finding: Finding, source: string): AstNode | undefined {
  const calls: AstNode[] = [];
  walk(ast, (node) => {
    if (node.type === 'CallExpression' && node.loc?.start.line === finding.line) calls.push(node);
  });
  const snippet = finding.snippet ?? '';
  for (const call of calls) {
    if (snippetOf(source, call) === snippet) return call;
  }
  calls.sort((a, b) => (a.range?.[0] ?? 0) - (b.range?.[0] ?? 0) || (b.range?.[1] ?? 0) - (a.range?.[1] ?? 0));
  return calls[0];
}

function suppressionPackage(call: AstNode, sinkClass: string, clearers: readonly ModelEntry[], routeByFn: Map<AstNode, ClearMark[]>): string | undefined {
  const arg = call.type === 'CallExpression' ? call.arguments[0] : undefined;
  if (arg === undefined || arg.type === 'SpreadElement') return undefined;
  const fn = enclosingFunction(call);
  const line = call.loc?.start.line ?? 0;
  const route = fn === undefined ? [] : (routeByFn.get(fn) ?? []);
  const marks = fn === undefined ? route : marksBefore(fn, line, clearers, route);
  const aliases = fn === undefined ? new Map<string, string>() : aliasesBefore(fn, line);
  const covered = coverNode(arg, sinkClass, marks.filter((mark) => mark.sinkClass === sinkClass), aliases, clearers);
  if (covered.blocked || covered.packageName === undefined) return undefined;
  return covered.packageName;
}

export async function applyModelSuppressions(
  cwd: string,
  findings: readonly Finding[],
): Promise<{ findings: Finding[]; suppressed: Finding[]; info: string[] }> {
  const { active, info } = resolveModelPacks(cwd);
  const clearers = active.filter((entry) => entry.kind === 'sanitizer' || entry.kind === 'validator');
  if (clearers.length === 0) return { findings: [...findings], suppressed: [], info };
  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    if (finding.file === undefined || !RULE_CLASS.has(finding.ruleId)) continue;
    const list = byFile.get(finding.file) ?? [];
    list.push(finding);
    byFile.set(finding.file, list);
  }
  const suppressedIds = new Map<string, string>();
  for (const [file, group] of byFile) {
    let source: string;
    try {
      source = await readFile(join(cwd, file), 'utf8');
    } catch {
      continue;
    }
    const ast = await parseCode(source);
    if (ast === undefined) continue;
    attachParents(ast);
    const named = namedFunctions(ast);
    const routeByFn = new Map<AstNode, ClearMark[]>();
    walk(ast, (node) => {
      if (!isRouteCall(node) || node.type !== 'CallExpression') return;
      const marks: ClearMark[] = [];
      for (const arg of node.arguments) {
        if (arg.type === 'SpreadElement') continue;
        for (const call of callsOf(arg)) {
          for (const entry of clearers) marks.push(...marksFrom(entry, call, 0));
        }
      }
      if (marks.length === 0) return;
      for (const arg of node.arguments) {
        if (arg.type === 'SpreadElement') continue;
        for (const handler of handlersOf(arg, named)) {
          const prior = routeByFn.get(handler) ?? [];
          routeByFn.set(handler, [...prior, ...marks]);
        }
      }
    });
    for (const finding of group) {
      const sinkClass = RULE_CLASS.get(finding.ruleId);
      if (sinkClass === undefined) continue;
      const call = sinkCall(ast, finding, source);
      if (call === undefined) continue;
      const packageName = suppressionPackage(call, sinkClass, clearers, routeByFn);
      if (packageName !== undefined) suppressedIds.set(finding.id, packageName);
    }
  }
  const suppressed = sortFindings(
    findings
      .filter((finding) => suppressedIds.has(finding.id))
      .map((finding) => ({ ...finding, suppressedBy: `model:${suppressedIds.get(finding.id) ?? ''}` })),
  );
  return {
    findings: findings.filter((finding) => !suppressedIds.has(finding.id)),
    suppressed,
    info,
  };
}
