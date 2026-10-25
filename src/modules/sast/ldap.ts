import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { makeFindingId, type Finding } from '../../core/finding.js';
import { calleeName, literalString, walk } from './ast.js';
import { analyzeFile, nodeIsTainted, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

const METHODS = new Set(['search', 'compare', 'modify', 'bind']);
const OPTION_KEYS = new Set(['filter', 'dn', 'base', 'baseDN']);

function importsLdap(source: string): boolean {
  return /(?:from|require\()\s*['"][^'"]*ldap/i.test(source);
}

function receiverIsLdap(node: AstNode): boolean {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return false;}
  const object = node.callee.object;
  return object.type === 'Identifier' && /ldap/i.test(object.name);
}

function optionTainted(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'ObjectExpression') {return false;}
  for (const prop of node.properties) {
    if (prop.type !== 'Property') {continue;}
    const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
    if (key !== undefined && OPTION_KEYS.has(key) && nodeIsTainted(prop.value, facts)) {return true;}
  }
  return false;
}

function callTainted(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'CallExpression') {return false;}
  for (const arg of node.arguments) {
    if (arg.type === 'SpreadElement') {continue;}
    if (nodeIsTainted(arg, facts) || optionTainted(arg, facts)) {return true;}
  }
  return false;
}

function ldapHit(filename: string, source: string, node: AstNode): Finding {
  const line = node.loc?.start.line;
  const snippet = node.range === undefined ? '' : source.slice(node.range[0], node.range[1]).replace(/\s+/g, ' ').trim().slice(0, 120);
  return {
    id: makeFindingId('SAST-LDAP-001', filename, `${line ?? 0}|${snippet}`),
    ruleId: 'SAST-LDAP-001',
    module: 'sast',
    title: 'LDAP injection',
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-90',
    file: filename,
    line,
    column: node.loc?.start.column,
    snippet,
    message: 'Request data reaches an LDAP filter or DN.',
    remediation: 'Escape the LDAP value, or pass a literal filter.',
    references: ['CWE-90'],
  };
}

async function parseLdap(source: string): Promise<AstNode> {
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

export async function ldapFindings(filename: string, source: string): Promise<Finding[]> {
  if (!/ldap/i.test(source)) {return [];}
  const imported = importsLdap(source);
  let ast: AstNode;
  try {
    ast = await parseLdap(source);
  } catch {
    return [];
  }
  const facts = analyzeFile(ast);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (node.type !== 'CallExpression') {return;}
    const name = calleeName(node);
    if (name === undefined || !METHODS.has(name)) {return;}
    if (!imported && !receiverIsLdap(node)) {return;}
    if (!callTainted(node, facts)) {return;}
    findings.push(ldapHit(filename, source, node));
  });
  return findings;
}

export async function ldapOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const rel of files) {
    if (!/\.[cm]?[jt]sx?$/.test(rel)) {continue;}
    try {
      findings.push(...(await ldapFindings(rel, await readFile(join(cwd, rel), 'utf8'))));
    } catch {
      continue;
    }
  }
  return findings;
}
