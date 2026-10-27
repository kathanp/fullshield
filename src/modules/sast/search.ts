import type { Finding } from '../../core/finding.js';
import { calleeName, literalString, walk } from './ast.js';
import { namedValueTainted, parseSource, sastHit, scanJsFiles } from './fileScan.js';
import { analyzeFile, nodeIsTainted, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

const SEARCH_IMPORT = /(?:from|require\()\s*['"](?:@elastic\/elasticsearch|@opensearch-project\/opensearch|elasticsearch)(?:\/[^'"]*)?['"]/;
const Q_KEYS = new Set(['q']);

function objectProp(node: AstNode, name: string): AstNode | undefined {
  if (node.type !== 'ObjectExpression') {return undefined;}
  for (const prop of node.properties) {
    if (prop.type !== 'Property') {continue;}
    const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
    if (key === name) {return prop.value;}
  }
  return undefined;
}

function queryStringTainted(arg: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (namedValueTainted(arg, facts, Q_KEYS)) {return true;}
  const query = objectProp(arg, 'query');
  if (query === undefined) {return false;}
  const queryString = objectProp(query, 'query_string');
  if (queryString === undefined) {return false;}
  const text = objectProp(queryString, 'query');
  return text !== undefined && nodeIsTainted(text, facts);
}

function searchCall(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'CallExpression' || calleeName(node) !== 'search') {return false;}
  const first = node.arguments[0];
  return first !== undefined && first.type !== 'SpreadElement' && queryStringTainted(first, facts);
}

function searchHit(filename: string, source: string, node: AstNode): Finding {
  return sastHit({
    ruleId: 'SAST-SEARCH-001',
    title: 'Search query injection',
    cwe: 'CWE-943',
    message: 'Request data is passed into a search query.',
    remediation: 'Pass a literal query, or build a structured query without string concatenation.',
    filename,
    source,
    node,
  });
}

export async function searchFindings(filename: string, source: string): Promise<Finding[]> {
  if (!SEARCH_IMPORT.test(source)) {return [];}
  const ast = await parseSource(source);
  if (ast === null) {return [];}
  const facts = analyzeFile(ast);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (searchCall(node, facts)) {findings.push(searchHit(filename, source, node));}
  });
  return findings;
}

export async function searchOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  return scanJsFiles(cwd, files, searchFindings);
}
