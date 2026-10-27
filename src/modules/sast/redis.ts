import type { Finding } from '../../core/finding.js';
import { calleeName, walk } from './ast.js';
import { callArgTainted, parseSource, sastHit, scanJsFiles } from './fileScan.js';
import { analyzeFile, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

const REDIS_IMPORT = /(?:from|require\()\s*['"](?:redis|ioredis)(?:\/[^'"]*)?['"]/;
const METHODS = new Set(['eval', 'evalSha', 'evalsha', 'call', 'sendCommand']);

function redisCall(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  return name !== undefined && METHODS.has(name) && callArgTainted(node, facts);
}

function redisHit(filename: string, source: string, node: AstNode): Finding {
  return sastHit({
    ruleId: 'SAST-REDIS-001',
    title: 'Redis command injection',
    cwe: 'CWE-94',
    message: 'Request data is passed to a Redis script or arbitrary command.',
    remediation: 'Pass a literal script or command, or allow only a fixed list.',
    filename,
    source,
    node,
  });
}

export async function redisFindings(filename: string, source: string): Promise<Finding[]> {
  if (!REDIS_IMPORT.test(source)) {return [];}
  const ast = await parseSource(source);
  if (ast === null) {return [];}
  const facts = analyzeFile(ast);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (redisCall(node, facts)) {findings.push(redisHit(filename, source, node));}
  });
  return findings;
}

export async function redisOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  return scanJsFiles(cwd, files, redisFindings);
}
