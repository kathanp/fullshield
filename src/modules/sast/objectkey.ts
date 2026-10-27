import type { Finding } from '../../core/finding.js';
import { calleeName, walk } from './ast.js';
import { namedValueTainted, parseSource, sastHit, scanJsFiles } from './fileScan.js';
import { analyzeFile, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

const S3_IMPORT = /(?:from|require\()\s*['"](?:@aws-sdk\/client-s3|aws-sdk)(?:\/[^'"]*)?['"]/;
const COMMANDS = new Set(['GetObjectCommand', 'PutObjectCommand', 'DeleteObjectCommand', 'ListObjectsV2Command']);
const METHODS = new Set(['getObject', 'putObject', 'deleteObject', 'listObjectsV2']);
const KEY_FIELDS = new Set(['Key', 'Prefix']);

function inputTainted(arg: AstNode | undefined, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  return arg !== undefined && arg.type !== 'SpreadElement' && namedValueTainted(arg, facts, KEY_FIELDS);
}

function objectKeySink(node: AstNode, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type === 'NewExpression') {
    const name = calleeName(node);
    return name !== undefined && COMMANDS.has(name) && inputTainted(node.arguments[0], facts);
  }
  if (node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  return name !== undefined && METHODS.has(name) && inputTainted(node.arguments[0], facts);
}

function objectKeyHit(filename: string, source: string, node: AstNode): Finding {
  return sastHit({
    ruleId: 'SAST-OBJECTKEY-001',
    title: 'Object-storage key from request data',
    cwe: 'CWE-22',
    message: 'Request data is used as an object-storage key or prefix.',
    remediation: 'Pass a literal key, or map request data onto an allowlist of keys.',
    filename,
    source,
    node,
  });
}

export async function objectkeyFindings(filename: string, source: string): Promise<Finding[]> {
  if (!S3_IMPORT.test(source)) {return [];}
  const ast = await parseSource(source);
  if (ast === null) {return [];}
  const facts = analyzeFile(ast);
  const findings: Finding[] = [];
  walk(ast, (node) => {
    if (objectKeySink(node, facts)) {findings.push(objectKeyHit(filename, source, node));}
  });
  return findings;
}

export async function objectkeyOnFiles(cwd: string, files: readonly string[]): Promise<Finding[]> {
  return scanJsFiles(cwd, files, objectkeyFindings);
}
