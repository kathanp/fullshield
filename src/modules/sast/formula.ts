import type { Finding } from '../../core/finding.js';
import { calleeName, literalString, walk } from './ast.js';
import { parseSource, sastHit, scanJsFiles } from './fileScan.js';
import { analyzeFile, nodeIsTainted, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

const CSV_IMPORT = /(?:from|require\()\s*['"](?:csv-stringify|fast-csv|json2csv|csv)(?:\/[^'"]*)?['"]/;
const WRITERS = new Set(['stringify', 'write', 'writeToPath', 'format']);
const RESPONSE_NAMES = new Set(['res', 'resp', 'response', 'reply']);

function receiverName(callee: AstNode): string | undefined {
  if (callee.type !== 'MemberExpression' || callee.object.type !== 'Identifier') {return undefined;}
  return callee.object.name;
}

function argTainted(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'CallExpression') {return false;}
  for (const arg of node.arguments) {
    if (arg.type !== 'SpreadElement' && nodeIsTainted(arg, facts)) {return true;}
  }
  return false;
}

function csvWrite(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  if (name !== 'writeFile' && name !== 'writeFileSync') {return false;}
  const path = node.arguments[0];
  const data = node.arguments[1];
  if (path === undefined || path.type === 'SpreadElement') {return false;}
  if (data === undefined || data.type === 'SpreadElement') {return false;}
  const text = literalString(path);
  return text !== undefined && text.endsWith('.csv') && nodeIsTainted(data, facts);
}

function responseWriter(callee: AstNode, name: string): boolean {
  if (name !== 'write' && name !== 'format') {return false;}
  const receiver = receiverName(callee);
  return receiver !== undefined && RESPONSE_NAMES.has(receiver);
}

function formulaCall(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>, imported: boolean): boolean {
  if (csvWrite(node, facts)) {return true;}
  if (!imported || node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  if (name === undefined || !WRITERS.has(name) || responseWriter(node.callee, name)) {return false;}
  return argTainted(node, facts);
}

function formulaHit(filename: string, source: string, node: AstNode): Finding {
  return sastHit({
    ruleId: 'SAST-FORMULA-001',
    title: 'Spreadsheet formula injection',
    cwe: 'CWE-1236',
    message: 'Request data is written into a spreadsheet or CSV.',
    remediation: 'Prefix a user cell that starts with =, +, -, or @, or write a literal row.',
    filename,
    source,
    node,
  });
}

export async function formulaFindings(filename: string, source: string): Promise<Finding[]> {
  const imported = CSV_IMPORT.test(source);
  const ast = await parseSource(source);
  if (ast === null) {return [];}
  const facts = analyzeFile(ast);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (formulaCall(node, facts, imported)) {findings.push(formulaHit(filename, source, node));}
  });
  return findings;
}

export async function formulaOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  return scanJsFiles(cwd, files, formulaFindings);
}
