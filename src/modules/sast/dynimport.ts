import type { Finding } from '../../core/finding.js';
import { walk } from './ast.js';
import { parseSource, sastHit, scanJsFiles } from './fileScan.js';
import { analyzeFile, nodeIsTainted, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

function importTainted(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  return node.type === 'ImportExpression' && nodeIsTainted(node.source, facts);
}

function dynHit(filename: string, source: string, node: AstNode): Finding {
  return sastHit({
    ruleId: 'SAST-DYNIMPORT-001',
    title: 'Dynamic import of request data',
    cwe: 'CWE-829',
    message: 'import() is called with request data.',
    remediation: 'Import a string literal, or allow only a fixed list of specifiers.',
    filename,
    source,
    node,
  });
}

export async function dynimportFindings(filename: string, source: string): Promise<Finding[]> {
  const ast = await parseSource(source);
  if (ast === null) {return [];}
  const facts = analyzeFile(ast);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (importTainted(node, facts)) {findings.push(dynHit(filename, source, node));}
  });
  return findings;
}

export async function dynimportOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  return scanJsFiles(cwd, files, dynimportFindings);
}
