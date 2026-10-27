import type { Finding } from '../../core/finding.js';
import { calleeName, walk } from './ast.js';
import { namedValueTainted, parseSource, sastHit, scanJsFiles } from './fileScan.js';
import { analyzeFile, nodeIsTainted, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

const WORKER_IMPORT = /(?:from|require\()\s*['"](?:node:)?worker_threads['"]/;
const WORKER_DATA = new Set(['workerData']);

function workerSink(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'NewExpression' || calleeName(node) !== 'Worker') {return false;}
  const path = node.arguments[0];
  if (path !== undefined && path.type !== 'SpreadElement' && nodeIsTainted(path, facts)) {return true;}
  const opts = node.arguments[1];
  return opts !== undefined && opts.type !== 'SpreadElement' && namedValueTainted(opts, facts, WORKER_DATA);
}

function workerHit(filename: string, source: string, node: AstNode): Finding {
  return sastHit({
    ruleId: 'SAST-WORKER-001',
    title: 'Worker entry from request data',
    cwe: 'CWE-94',
    message: 'Request data is passed as a worker module path or workerData.',
    remediation: 'Pass a literal module path and literal workerData.',
    filename,
    source,
    node,
  });
}

export async function workerFindings(filename: string, source: string): Promise<Finding[]> {
  if (!WORKER_IMPORT.test(source)) {return [];}
  const ast = await parseSource(source);
  if (ast === null) {return [];}
  const facts = analyzeFile(ast);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (workerSink(node, facts)) {findings.push(workerHit(filename, source, node));}
  });
  return findings;
}

export async function workerOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  return scanJsFiles(cwd, files, workerFindings);
}
