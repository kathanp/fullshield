import type { Finding } from '../../core/finding.js';
import { calleeName, walk } from './ast.js';
import { namedValueTainted, parseSource, sastHit, scanJsFiles } from './fileScan.js';
import { analyzeFile, nodeIsTainted, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

const HEADER_METHODS = new Set(['setHeader', 'append', 'header', 'set']);

function writeHeadTainted(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'CallExpression') {return false;}
  for (const arg of node.arguments) {
    if (arg.type === 'SpreadElement') {continue;}
    if (namedValueTainted(arg, facts)) {return true;}
  }
  return false;
}

function methodHeaderTainted(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'CallExpression') {return false;}
  const value = node.arguments[1];
  if (value !== undefined && value.type !== 'SpreadElement' && nodeIsTainted(value, facts)) {return true;}
  const first = node.arguments[0];
  if (first === undefined || first.type === 'SpreadElement') {return false;}
  return namedValueTainted(first, facts);
}

function headerTainted(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  if (name === 'writeHead') {return writeHeadTainted(node, facts);}
  if (name === undefined || !HEADER_METHODS.has(name)) {return false;}
  return methodHeaderTainted(node, facts);
}

function crlfHit(filename: string, source: string, node: AstNode): Finding {
  return sastHit({
    ruleId: 'SAST-CRLF-001',
    title: 'HTTP header injection',
    cwe: 'CWE-113',
    message: 'Request data is written into an HTTP header.',
    remediation: 'Set the header to a literal, or strip CR and LF from the value.',
    filename,
    source,
    node,
  });
}

export async function crlfFindings(filename: string, source: string): Promise<Finding[]> {
  const ast = await parseSource(source);
  if (ast === null) {return [];}
  const facts = analyzeFile(ast);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (headerTainted(node, facts)) {findings.push(crlfHit(filename, source, node));}
  });
  return findings;
}

export async function crlfOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  return scanJsFiles(cwd, files, crlfFindings);
}
