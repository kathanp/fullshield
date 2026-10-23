/**
 * Phase 464. Permission-model suggestion.
 * Off unless FULLSHIELD_EXPERIMENTAL_PERMMODEL=1.
 * Flag off: no suggestion is returned.
 * A dynamic path produces a gap and never a star allow. Apply stays review.
 */
import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PERMMODEL';

function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PermissionFacts {
  fsReads: string[];
  hosts: string[];
  childProcess: boolean;
  dynamicPaths: string[];
}

export interface PermissionSuggestion {
  command: string | null;
  gap: string | null;
  disposition: 'review';
}

function calleeName(node: TSESTree.Node): string {
  if (node.type === 'Identifier') {
    return node.name;
  }
  if (node.type === 'MemberExpression' && node.property.type === 'Identifier') {
    return node.property.name;
  }
  return '';
}

function literalArg(node: TSESTree.Node | undefined): string | null {
  if (node !== undefined && node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }
  return null;
}

function hostOf(url: string): string | null {
  const match = /^https?:\/\/([^/]+)/.exec(url);
  return match?.[1] ?? null;
}

function astNode(value: unknown): value is TSESTree.Node {
  return typeof value === 'object' && value !== null && 'type' in value;
}

function walkChild(child: unknown, visit: (node: TSESTree.Node) => void): void {
  if (Array.isArray(child)) {
    for (const item of child) {
      if (astNode(item)) {
        visit(item);
      }
    }
    return;
  }
  if (astNode(child)) {
    visit(child);
  }
}

function noteChildImport(node: TSESTree.Node, facts: PermissionFacts): void {
  if (node.type === 'ImportDeclaration' && node.source.value === 'node:child_process') {
    facts.childProcess = true;
  }
}

function noteRequire(node: TSESTree.CallExpression, facts: PermissionFacts): void {
  if (node.callee.type !== 'Identifier' || node.callee.name !== 'require') {
    return;
  }
  const spec = literalArg(node.arguments[0]);
  if (spec === 'child_process' || spec === 'node:child_process') {
    facts.childProcess = true;
  }
}

function noteRead(node: TSESTree.CallExpression, facts: PermissionFacts): void {
  const name = calleeName(node.callee);
  if (name !== 'readFile' && name !== 'readFileSync') {
    return;
  }
  const path = literalArg(node.arguments[0]);
  if (path === null) {
    facts.dynamicPaths.push('fs read is not a literal');
    return;
  }
  facts.fsReads.push(path);
}

function noteFetch(node: TSESTree.CallExpression, facts: PermissionFacts): void {
  if (calleeName(node.callee) !== 'fetch') {
    return;
  }
  const host = hostOf(literalArg(node.arguments[0]) ?? '');
  if (host !== null) {
    facts.hosts.push(host);
  }
}

function noteCall(node: TSESTree.Node, facts: PermissionFacts): void {
  if (node.type !== 'CallExpression') {
    return;
  }
  noteRequire(node, facts);
  noteRead(node, facts);
  noteFetch(node, facts);
}

function visitPerm(node: TSESTree.Node, facts: PermissionFacts): void {
  noteChildImport(node, facts);
  noteCall(node, facts);
  for (const child of Object.values(node as unknown as Record<string, unknown>)) {
    walkChild(child, (item) => {
      visitPerm(item, facts);
    });
  }
}

export function collectFacts(files: Readonly<Record<string, string>>): PermissionFacts {
  const facts: PermissionFacts = { fsReads: [], hosts: [], childProcess: false, dynamicPaths: [] };
  for (const text of Object.values(files)) {
    let ast: TSESTree.Program;
    try {
      ast = parse(text, { loc: false, range: false, jsx: false });
    } catch {
      continue;
    }
    visitPerm(ast, facts);
  }
  return facts;
}

export function suggestPermission(facts: PermissionFacts): PermissionSuggestion | null {
  if (!enabled()) {
    return null;
  }
  const gap = facts.dynamicPaths.length > 0 ? `gap: ${facts.dynamicPaths.join('; ')}` : null;
  const allows = [
    ...facts.fsReads.map((path) => `--allow-fs-read=${path}`),
    ...facts.hosts.map((host) => `--allow-net=${host}`),
    ...(facts.childProcess ? ['--allow-child-process'] : []),
  ];
  const command = allows.length === 0 ? null : `node --permission ${allows.join(' ')}`;
  return { command, gap, disposition: 'review' };
}

export function permissionApplyDisposition(): 'review' {
  return 'review';
}
