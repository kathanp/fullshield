import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { makeFindingId, type Finding } from '../../core/finding.js';
import { calleeName, literalString, propName, walk } from './ast.js';
import { analyzeFile, nodeIsTainted } from './taint.js';
import type { AstNode } from './types.js';

const FS_IMPORT = /(?:from|require\()\s*['"](?:node:)?fs['"]/;
const HTML = /<[A-Za-z][^>]*>/;
const PROTO_GUARD = /===\s*['"]__proto__['"]|['"]__proto__['"]\s*===/;
const SSRF_KEYS = new Set(['hostname', 'host', 'href', 'path']);

interface Copy {
  ruleId: string;
  title: string;
  message: string;
  cwe: string;
  remediation: string;
}

function hit(filename: string, source: string, node: AstNode, copy: Copy): Finding {
  const line = node.loc?.start.line;
  const snippet = node.range === undefined ? '' : source.slice(node.range[0], node.range[1]).replace(/\s+/g, ' ').trim().slice(0, 120);
  return {
    id: makeFindingId(copy.ruleId, filename, `${line ?? 0}|${snippet}`),
    ruleId: copy.ruleId,
    module: 'sast',
    title: copy.title,
    severity: 'high',
    confidence: 'high',
    cwe: copy.cwe,
    file: filename,
    line,
    column: node.loc?.start.column,
    snippet,
    message: copy.message,
    remediation: copy.remediation,
    references: [copy.cwe],
  };
}

function keyOf(prop: AstNode): string | undefined {
  if (prop.type !== 'Property') {return undefined;}
  return prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
}

function hasHtml(node: AstNode, source: string): boolean {
  if (HTML.test(source)) {return true;}
  const text = literalString(node);
  if (text !== undefined && HTML.test(text)) {return true;}
  if (node.type !== 'TemplateLiteral') {return false;}
  return node.quasis.some((quasi) => HTML.test(quasi.value.cooked ?? quasi.value.raw));
}

function fsCall(node: AstNode, source: string): boolean {
  if (node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  if (name !== 'glob' && name !== 'opendir') {return false;}
  if (FS_IMPORT.test(source)) {return true;}
  if (node.callee.type !== 'MemberExpression') {return false;}
  const object = node.callee.object;
  if (object.type === 'Identifier' && object.name === 'fs') {return true;}
  return object.type === 'MemberExpression' && propName(object) === 'promises';
}

function bunFile(node: AstNode): boolean {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return false;}
  const object = node.callee.object;
  return object.type === 'Identifier' && object.name === 'Bun' && propName(node.callee) === 'file';
}

function httpRequest(node: AstNode): boolean {
  if (node.type !== 'CallExpression' || calleeName(node) !== 'request' || node.callee.type !== 'MemberExpression') {return false;}
  const object = node.callee.object;
  return object.type === 'Identifier' && (object.name === 'http' || object.name === 'https');
}

function jwtVerify(node: AstNode): boolean {
  if (node.type !== 'CallExpression' || calleeName(node) !== 'verify' || node.callee.type !== 'MemberExpression') {return false;}
  const object = node.callee.object;
  return object.type === 'Identifier' && /^(jwt|jsonwebtoken)$/i.test(object.name);
}

function algorithmsOf(node: AstNode): AstNode | undefined {
  if (node.type !== 'CallExpression') {return undefined;}
  const opts = node.arguments[2];
  if (opts === undefined || opts.type !== 'ObjectExpression') {return undefined;}
  for (const prop of opts.properties) {
    if (keyOf(prop) === 'algorithms' && prop.type === 'Property') {return prop.value;}
  }
  return undefined;
}

async function parseSource(source: string): Promise<AstNode> {
  const { parse } = await import('@typescript-eslint/typescript-estree');
  return parse(source, {
    loc: true,
    range: true,
    comment: false,
    jsx: true,
    errorOnUnknownASTType: false,
    errorOnTypeScriptSyntacticAndSemanticIssues: false,
  });
}

function xssEnd(filename: string, source: string, node: AstNode, tainted: (n: AstNode) => boolean): Finding | undefined {
  if (node.type !== 'CallExpression' || calleeName(node) !== 'end') {return undefined;}
  const arg = node.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement' || !tainted(arg) || !hasHtml(arg, source)) {return undefined;}
  return hit(filename, source, node, {
    ruleId: 'SAST-XSS-001',
    title: 'Reflected XSS via HTML response',
    message: 'Tainted input is interpolated into an HTML response.',
    cwe: 'CWE-79',
    remediation: 'Escape the value, or send a literal body.',
  });
}

function ssrfOptions(filename: string, source: string, node: AstNode, tainted: (n: AstNode) => boolean): Finding | undefined {
  if (!httpRequest(node) || node.type !== 'CallExpression') {return undefined;}
  const arg = node.arguments[0];
  if (arg === undefined || arg.type !== 'ObjectExpression' || tainted(arg)) {return undefined;}
  const bad = arg.properties.some((prop) => {
    const key = keyOf(prop);
    return prop.type === 'Property' && key !== undefined && SSRF_KEYS.has(key) && tainted(prop.value);
  });
  if (!bad) {return undefined;}
  return hit(filename, source, node, {
    ruleId: 'SAST-SSRF-001',
    title: 'SSRF via tainted URL',
    message: 'Tainted input is the host or path of http.request.',
    cwe: 'CWE-918',
    remediation: 'Use a fixed host, or allow-list the URL.',
  });
}

function pathExtra(filename: string, source: string, node: AstNode, tainted: (n: AstNode) => boolean): Finding | undefined {
  if (node.type !== 'CallExpression') {return undefined;}
  if (!bunFile(node) && !fsCall(node, source)) {return undefined;}
  const arg = node.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement' || !tainted(arg)) {return undefined;}
  return hit(filename, source, node, {
    ruleId: 'SAST-PATH-001',
    title: 'Path traversal via unsanitized file path',
    message: 'Tainted input is used as a file path.',
    cwe: 'CWE-22',
    remediation: 'Resolve the path against a fixed base and check the prefix.',
  });
}

function locationRedirect(filename: string, source: string, node: AstNode, tainted: (n: AstNode) => boolean): Finding | undefined {
  if (node.type !== 'CallExpression' || calleeName(node) !== 'location') {return undefined;}
  const arg = node.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement' || !tainted(arg)) {return undefined;}
  return hit(filename, source, node, {
    ruleId: 'SAST-REDIRECT-001',
    title: 'Open redirect',
    message: 'Tainted input is passed to location.',
    cwe: 'CWE-601',
    remediation: 'Redirect only to a fixed path.',
  });
}

function jwtAlgorithms(filename: string, source: string, node: AstNode): Finding | undefined {
  if (!jwtVerify(node)) {return undefined;}
  const algorithms = algorithmsOf(node);
  if (algorithms === undefined) {return undefined;}
  const empty = algorithms.type === 'ArrayExpression' && algorithms.elements.length === 0;
  if (!empty && algorithms.type === 'ArrayExpression') {return undefined;}
  return hit(filename, source, node, {
    ruleId: 'SAST-JWT-001',
    title: 'Insecure JWT verification',
    message: 'jwt.verify is called without a literal algorithm allow-list.',
    cwe: 'CWE-347',
    remediation: 'Pass a literal algorithms array that does not include none.',
  });
}

function assignProto(filename: string, source: string, node: AstNode, tainted: (n: AstNode) => boolean): Finding | undefined {
  if (PROTO_GUARD.test(source) || node.type !== 'CallExpression' || calleeName(node) !== 'assign') {return undefined;}
  const bad = node.arguments.some((arg) => arg.type !== 'SpreadElement' && tainted(arg));
  if (!bad) {return undefined;}
  return hit(filename, source, node, {
    ruleId: 'SAST-PROTO-001',
    title: 'Prototype pollution via recursive merge',
    message: 'assign copies request data onto an object.',
    cwe: 'CWE-1321',
    remediation: 'Copy an allow-list of fields, and reject __proto__.',
  });
}

export async function deepFindings(filename: string, source: string): Promise<Finding[]> {
  let ast: AstNode;
  try {
    ast = await parseSource(source);
  } catch {
    return [];
  }
  const facts = analyzeFile(ast);
  const tainted = (node: AstNode) => nodeIsTainted(node, facts);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    const found = xssEnd(filename, source, node, tainted)
      ?? ssrfOptions(filename, source, node, tainted)
      ?? pathExtra(filename, source, node, tainted)
      ?? locationRedirect(filename, source, node, tainted)
      ?? jwtAlgorithms(filename, source, node)
      ?? assignProto(filename, source, node, tainted);
    if (found !== undefined) {findings.push(found);}
  });
  return findings;
}

export async function deepOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const rel of files) {
    if (!/\.[cm]?[jt]sx?$/.test(rel)) {continue;}
    try {
      findings.push(...(await deepFindings(rel, await readFile(join(cwd, rel), 'utf8'))));
    } catch {
      continue;
    }
  }
  return findings;
}
