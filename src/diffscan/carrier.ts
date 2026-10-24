import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { makeFindingId, type Finding } from '../core/finding.js';
import { calleeName, isFunctionNode, propName, walk } from '../modules/sast/ast.js';
import { collectRequires } from '../modules/sast/interproc.js';
import { analyzeFile, nodeIsTainted, type ScopeFacts } from '../modules/sast/taint.js';
import type { AstNode } from '../modules/sast/types.js';
import { diffChangedFiles } from './frontier.js';

interface Carrier {
  file: string;
  name: string;
  line: number;
}

interface SinkHit {
  ruleId: string;
  title: string;
  cwe: string;
}

const BY_NAME = new Map<string, SinkHit>([
  ['query', { ruleId: 'SAST-SQLI-001', title: 'SQL injection via string concatenation', cwe: 'CWE-89' }],
  ['execute', { ruleId: 'SAST-SQLI-001', title: 'SQL injection via string concatenation', cwe: 'CWE-89' }],
  ['exec', { ruleId: 'SAST-CMDI-001', title: 'Command injection via shell execution', cwe: 'CWE-78' }],
  ['execSync', { ruleId: 'SAST-CMDI-001', title: 'Command injection via shell execution', cwe: 'CWE-78' }],
  ['readFile', { ruleId: 'SAST-PATH-001', title: 'Path traversal via unsanitized file path', cwe: 'CWE-22' }],
  ['readFileSync', { ruleId: 'SAST-PATH-001', title: 'Path traversal via unsanitized file path', cwe: 'CWE-22' }],
  ['find', { ruleId: 'SAST-NOSQLI-001', title: 'NoSQL injection via raw request object filter', cwe: 'CWE-943' }],
  ['findOne', { ruleId: 'SAST-NOSQLI-001', title: 'NoSQL injection via raw request object filter', cwe: 'CWE-943' }],
]);

function identifierSink(node: AstNode, name: string): SinkHit | undefined {
  if (node.type !== 'CallExpression' || node.callee.type !== 'Identifier') {return undefined;}
  if (name === 'fetch') {return { ruleId: 'SAST-SSRF-001', title: 'SSRF via tainted URL', cwe: 'CWE-918' };}
  if (name === 'eval') {return { ruleId: 'SAST-EVAL-001', title: 'Dynamic code execution with a non-literal', cwe: 'CWE-95' };}
  return undefined;
}

function responseSink(node: AstNode, source: string, name: string): SinkHit | undefined {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return undefined;}
  if (node.callee.object.type !== 'Identifier' || node.callee.object.name !== 'res') {return undefined;}
  if (name === 'redirect') {return { ruleId: 'SAST-REDIRECT-001', title: 'Open redirect', cwe: 'CWE-601' };}
  if (name !== 'send') {return undefined;}
  const arg = node.arguments[0];
  const text = arg === undefined || arg.type === 'SpreadElement' ? '' : source.slice(arg.range?.[0] ?? 0, arg.range?.[1] ?? 0);
  if (!text.includes('<')) {return undefined;}
  return { ruleId: 'SAST-XSS-001', title: 'Reflected XSS via HTML response', cwe: 'CWE-79' };
}

function sinkOf(node: AstNode, source: string): SinkHit | undefined {
  if (node.type !== 'CallExpression') {return undefined;}
  const name = calleeName(node);
  if (name === undefined) {return undefined;}
  return BY_NAME.get(name) ?? identifierSink(node, name) ?? responseSink(node, source, name);
}

function enclosingFunction(node: AstNode): AstNode | undefined {
  let parent: AstNode | undefined = (node as { parent?: AstNode }).parent;
  while (parent !== undefined) {
    if (isFunctionNode(parent)) {return parent;}
    parent = (parent as { parent?: AstNode }).parent;
  }
  return undefined;
}

function returnsRequest(fn: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  let yes = false;
  walk(fn, (node) => {
    if (enclosingFunction(node) !== fn) {return;}
    if (node.type === 'ReturnStatement' && node.argument !== null && nodeIsTainted(node.argument, facts)) {yes = true;}
  });
  return yes;
}

function carriersIn(file: string, ast: AstNode): Carrier[] {
  const facts = analyzeFile(ast);
  const functions = new Map<string, AstNode>();
  walk(ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id !== null) {functions.set(node.id.name, node);}
  });
  const exported = new Set<string>();
  walk(ast, (node) => {noteExport(node, exported);});
  const found: Carrier[] = [];
  for (const name of exported) {
    const fn = functions.get(name);
    if (fn === undefined || !returnsRequest(fn, facts)) {continue;}
    found.push({ file, name, line: fn.loc?.start.line ?? 1 });
  }
  return found;
}

function exportRoot(left: AstNode): string | undefined {
  if (left.type !== 'MemberExpression') {return undefined;}
  if (left.object.type === 'Identifier') {return left.object.name;}
  if (left.object.type === 'MemberExpression' && left.object.object.type === 'Identifier') {return left.object.object.name;}
  return undefined;
}

function noteObjectExports(node: AstNode, exported: Set<string>): void {
  if (node.type !== 'AssignmentExpression' || node.left.type !== 'MemberExpression' || node.right.type !== 'ObjectExpression') {return;}
  if (exportRoot(node.left) !== 'module' || propName(node.left) !== 'exports') {return;}
  for (const prop of node.right.properties) {
    if (prop.type === 'Property' && prop.value.type === 'Identifier') {exported.add(prop.value.name);}
  }
}

function noteExport(node: AstNode, exported: Set<string>): void {
  if (node.type === 'ExportNamedDeclaration' && node.declaration?.type === 'FunctionDeclaration' && node.declaration.id !== null) {
    exported.add(node.declaration.id.name);
  }
  noteObjectExports(node, exported);
  if (node.type !== 'AssignmentExpression' || node.left.type !== 'MemberExpression') {return;}
  if (exportRoot(node.left) !== 'exports' || node.left.object.type !== 'Identifier') {return;}
  const name = propName(node.left);
  if (name !== undefined && node.right.type === 'Identifier') {exported.add(node.right.name);}
}

function argumentCalls(arg: AstNode, names: ReadonlyMap<string, string>): string | undefined {
  let hit: string | undefined;
  walk(arg, (node) => {
    if (hit !== undefined || node.type !== 'CallExpression' || node.callee.type !== 'Identifier') {return;}
    const spec = names.get(node.callee.name);
    if (spec !== undefined) {hit = spec;}
  });
  return hit;
}

function carrierFinding(
  node: AstNode,
  entry: { file: string; source: string },
  sink: { ruleId: string; title: string; cwe: string },
  carrier: Carrier,
): Finding {
  const start = node.range?.[0] ?? 0;
  const end = node.range?.[1] ?? 0;
  const snippet = entry.source.slice(start, end).replace(/\s+/g, ' ').trim().slice(0, 120);
  const line = node.loc?.start.line;
  const callee = node.type === 'CallExpression' ? (calleeName(node) ?? 'call') : 'call';
  return {
    id: makeFindingId(sink.ruleId, entry.file, `${line ?? 0}|${snippet}`),
    ruleId: sink.ruleId,
    module: 'sast',
    title: sink.title,
    severity: 'high',
    confidence: 'high',
    cwe: sink.cwe,
    file: entry.file,
    line,
    snippet,
    message: `Value returned from ${carrier.file} reaches ${callee}.`,
    remediation: 'Pass bound parameters. Do not build the sink argument from request input.',
    trace: [
      { file: carrier.file, line: carrier.line, note: `returned from ${carrier.name}` },
      { file: entry.file, line, note: callee },
    ],
  };
}

function findingsAt(
  node: AstNode,
  entry: { file: string; source: string },
  imports: ReadonlyMap<string, string>,
  byExport: ReadonlyMap<string, Carrier>,
): Finding[] {
  const sink = sinkOf(node, entry.source);
  if (sink === undefined || node.type !== 'CallExpression') {return [];}
  const found: Finding[] = [];
  for (const arg of node.arguments) {
    if (arg.type === 'SpreadElement') {continue;}
    const spec = argumentCalls(arg, imports);
    const carrier = spec === undefined ? undefined : byExport.get(spec);
    if (carrier === undefined) {continue;}
    found.push(carrierFinding(node, entry, sink, carrier));
  }
  return found;
}

export async function carrierFindings(cwd: string, files: readonly string[]): Promise<Finding[]> {
  const changed = new Set(diffChangedFiles().filter((rel) => files.includes(rel)));
  const { parse } = await import('@typescript-eslint/typescript-estree');
  const parsed: { file: string; source: string; ast: AstNode }[] = [];
  for (const file of files) {
    const source = await readFile(join(cwd, file), 'utf8');
    const ast = parse(source, {
      loc: true,
      range: true,
      comment: false,
      jsx: true,
      errorOnUnknownASTType: false,
      errorOnTypeScriptSyntacticAndSemanticIssues: false,
    }) as AstNode;
    parsed.push({ file, source, ast });
  }
  const byExport = new Map<string, Carrier>();
  for (const entry of parsed) {
    if (!changed.has(entry.file)) {continue;}
    for (const carrier of carriersIn(entry.file, entry.ast)) {
      byExport.set(`${carrier.file}#${carrier.name}`, carrier);
    }
  }
  if (byExport.size === 0) {return [];}
  const fileSet = new Set(parsed.map((entry) => entry.file));
  const findings: Finding[] = [];
  for (const entry of parsed) {
    const imports = collectRequires(entry.file, entry.ast, fileSet);
    walk(entry.ast, (node) => {
      findings.push(...findingsAt(node, entry, imports, byExport));
    });
  }
  return findings;
}
