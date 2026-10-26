import type { Finding } from '../../core/finding.js';
import { calleeName, walk } from './ast.js';
import { callArgTainted, parseSource, sastHit, scanJsFiles } from './fileScan.js';
import { analyzeFile, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

const BROWSER_IMPORT = /(?:from|require\()\s*['"](?:puppeteer-core|puppeteer|playwright|@playwright\/test)(?:\/[^'"]*)?['"]/;
const METHODS = new Set(['goto', 'setContent', 'pdf']);

function browserCall(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): string | undefined {
  if (node.type !== 'CallExpression') {return undefined;}
  const name = calleeName(node);
  if (name === undefined || !METHODS.has(name)) {return undefined;}
  if (!callArgTainted(node, facts)) {return undefined;}
  return name;
}

function browserHit(filename: string, source: string, node: AstNode, name: string): Finding {
  const cwe = name === 'setContent' ? 'CWE-79' : 'CWE-918';
  return sastHit({
    ruleId: 'SAST-BROWSER-001',
    title: 'Browser automation controlled by request data',
    cwe,
    message: 'Request data is passed to a browser-automation call.',
    remediation: 'Pass a literal URL or HTML body.',
    filename,
    source,
    node,
  });
}

export async function browserCtlFindings(filename: string, source: string): Promise<Finding[]> {
  if (!BROWSER_IMPORT.test(source)) {return [];}
  const ast = await parseSource(source);
  if (ast === null) {return [];}
  const facts = analyzeFile(ast);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    const name = browserCall(node, facts);
    if (name !== undefined) {findings.push(browserHit(filename, source, node, name));}
  });
  return findings;
}

export async function browserCtlOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  return scanJsFiles(cwd, files, browserCtlFindings);
}
