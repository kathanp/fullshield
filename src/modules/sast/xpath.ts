import type { Finding } from '../../core/finding.js';
import { calleeName, walk } from './ast.js';
import { callArgTainted, parseSource, sastHit, scanJsFiles } from './fileScan.js';
import { analyzeFile, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

const XPATH_IMPORT = /(?:from|require\()\s*['"](?:xpath|xpath\.js|libxmljs)(?:\/[^'"]*)?['"]/;
const METHODS = new Set(['select', 'select1', 'evaluate']);

function xpathCall(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  return name !== undefined && METHODS.has(name) && callArgTainted(node, facts);
}

function xpathHit(filename: string, source: string, node: AstNode): Finding {
  return sastHit({
    ruleId: 'SAST-XPATH-001',
    title: 'XPath injection',
    cwe: 'CWE-643',
    message: 'Request data is passed to an XPath expression.',
    remediation: 'Pass a literal XPath expression, or allow only a fixed list.',
    filename,
    source,
    node,
  });
}

export async function xpathFindings(filename: string, source: string): Promise<Finding[]> {
  if (!XPATH_IMPORT.test(source)) {return [];}
  const ast = await parseSource(source);
  if (ast === null) {return [];}
  const facts = analyzeFile(ast);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (xpathCall(node, facts)) {findings.push(xpathHit(filename, source, node));}
  });
  return findings;
}

export async function xpathOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  return scanJsFiles(cwd, files, xpathFindings);
}
