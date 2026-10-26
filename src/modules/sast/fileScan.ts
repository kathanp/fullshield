import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { makeFindingId, type Finding } from '../../core/finding.js';
import { literalString } from './ast.js';
import { nodeIsTainted, type ScopeFacts } from './taint.js';
import type { AstNode } from './types.js';

export interface HitInput {
  ruleId: string;
  title: string;
  cwe: string;
  message: string;
  remediation: string;
  filename: string;
  source: string;
  node: AstNode;
}

export async function parseSource(source: string): Promise<AstNode | null> {
  try {
    const { parse } = await import('@typescript-eslint/typescript-estree');
    return parse(source, {
      loc: true,
      range: true,
      comment: false,
      jsx: true,
      errorOnUnknownASTType: false,
      errorOnTypeScriptSyntacticAndSemanticIssues: false,
    });
  } catch {
    return null;
  }
}

export async function scanJsFiles(
  cwd: string,
  files: readonly string[],
  scan: (filename: string, source: string) => Promise<Finding[]>,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const rel of files) {
    if (!/\.[cm]?[jt]sx?$/.test(rel)) {continue;}
    try {
      findings.push(...(await scan(rel, await readFile(join(cwd, rel), 'utf8'))));
    } catch {
      continue;
    }
  }
  return findings;
}

export function sastHit(input: HitInput): Finding {
  const line = input.node.loc?.start.line;
  const snippet = input.node.range === undefined
    ? ''
    : input.source.slice(input.node.range[0], input.node.range[1]).replace(/\s+/g, ' ').trim().slice(0, 120);
  return {
    id: makeFindingId(input.ruleId, input.filename, `${line ?? 0}|${snippet}`),
    ruleId: input.ruleId,
    module: 'sast',
    title: input.title,
    severity: 'high',
    confidence: 'high',
    cwe: input.cwe,
    file: input.filename,
    line,
    column: input.node.loc?.start.column,
    snippet,
    message: input.message,
    remediation: input.remediation,
    references: [input.cwe],
  };
}

function keyAllowed(prop: TSESTree.Property, keys: ReadonlySet<string> | undefined): boolean {
  if (keys === undefined) {return true;}
  const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
  return key !== undefined && keys.has(key);
}

export function namedValueTainted(
  node: AstNode,
  facts: WeakMap<AstNode, ScopeFacts>,
  keys?: ReadonlySet<string>,
): boolean {
  if (node.type !== 'ObjectExpression') {return false;}
  for (const prop of node.properties) {
    if (prop.type !== 'Property') {continue;}
    if (!keyAllowed(prop, keys)) {continue;}
    if (nodeIsTainted(prop.value, facts)) {return true;}
  }
  return false;
}

export function callArgTainted(node: TSESTree.CallExpression, facts: WeakMap<AstNode, ScopeFacts>): boolean {
  for (const arg of node.arguments) {
    if (arg.type === 'SpreadElement') {continue;}
    if (nodeIsTainted(arg, facts)) {return true;}
    if (namedValueTainted(arg, facts)) {return true;}
  }
  return false;
}
