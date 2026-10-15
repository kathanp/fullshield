import type { TSESTree } from '@typescript-eslint/typescript-estree';

import type { AstNode } from './types.js';

export interface NodeWithParent {
  parent?: AstNode;
}

const SKIP_KEYS = new Set(['loc', 'range', 'type', 'parent']);

export function propName(node: TSESTree.MemberExpression): string | undefined {
  if (node.property.type === 'Identifier' && node.computed !== true) return node.property.name;
  if (node.property.type === 'Literal' && typeof node.property.value === 'string') {
    return node.property.value;
  }
  return undefined;
}

export function calleeName(node: TSESTree.CallExpression | TSESTree.NewExpression): string | undefined {
  if (node.callee.type === 'Identifier') return node.callee.name;
  if (node.callee.type === 'MemberExpression') return propName(node.callee);
  return undefined;
}

/** True when `method` appears on the callee chain (`createQueryBuilder().select().where()`). */
export function calleeChainHas(node: TSESTree.CallExpression, method: string): boolean {
  let current: AstNode | undefined = node.callee;
  for (let i = 0; i < 16 && current !== undefined; i += 1) {
    if (current.type === 'CallExpression') {
      if (calleeName(current) === method) return true;
      current = current.callee;
      continue;
    }
    if (current.type === 'MemberExpression') {
      if (propName(current) === method) return true;
      current = current.object;
      continue;
    }
    if (current.type === 'Identifier') return current.name === method;
    break;
  }
  return false;
}

export function literalString(node: AstNode | undefined): string | undefined {
  if (node === undefined) return undefined;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis[0]?.value.cooked ?? node.quasis[0]?.value.raw;
  }
  return undefined;
}

export function isLiteralExpr(node: AstNode | undefined): boolean {
  return literalString(node) !== undefined;
}

export function boundNames(pattern: AstNode | undefined): string[] {
  if (pattern === undefined) return [];
  if (pattern.type === 'Identifier') return [pattern.name];
  if (pattern.type === 'AssignmentPattern') return boundNames(pattern.left);
  if (pattern.type === 'RestElement') return boundNames(pattern.argument);
  if (pattern.type === 'ArrayPattern') {
    return pattern.elements.flatMap((el) => boundNames(el ?? undefined));
  }
  if (pattern.type === 'ObjectPattern') {
    return pattern.properties.flatMap((prop) => {
      if (prop.type === 'RestElement') return boundNames(prop.argument);
      return boundNames(prop.value);
    });
  }
  return [];
}

export function isFunctionNode(
  node: AstNode,
): node is TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression {
  return (
    node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression'
  );
}

export function enclosingScope(node: AstNode): AstNode {
  let current: AstNode | undefined = node;
  while (current !== undefined) {
    if (isFunctionNode(current) || current.type === 'Program') return current;
    current = (current as unknown as NodeWithParent).parent;
  }
  return node;
}

export function walk(node: AstNode, visit: (n: AstNode) => void): void {
  visit(node);
  for (const key of Object.keys(node) as Array<keyof AstNode>) {
    if (SKIP_KEYS.has(String(key))) continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) {
        if (child !== null && typeof child === 'object' && 'type' in child) {
          walk(child, visit);
        }
      }
    } else if (value !== null && typeof value === 'object' && 'type' in value) {
      walk(value, visit);
    }
  }
}

export function attachParents(node: AstNode, parent?: AstNode): void {
  (node as unknown as NodeWithParent).parent = parent;
  for (const key of Object.keys(node) as Array<keyof AstNode>) {
    if (SKIP_KEYS.has(String(key))) continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) {
        if (child !== null && typeof child === 'object' && 'type' in child) {
          attachParents(child, node);
        }
      }
    } else if (value !== null && typeof value === 'object' && 'type' in value) {
      attachParents(value, node);
    }
  }
}

export const REQUEST_SOURCE_PROPS = new Set(['query', 'body', 'params', 'headers', 'files']);
const SOURCE_PROPS = REQUEST_SOURCE_PROPS;

export function isTaintSource(node: AstNode): boolean {
  if (node.type !== 'MemberExpression') return false;
  const name = propName(node);
  if (node.object.type === 'Identifier' && node.object.name === 'req' && name !== undefined && SOURCE_PROPS.has(name)) {
    return true;
  }
  if (node.object.type === 'Identifier' && node.object.name === 'process' && name === 'argv') {
    return true;
  }
  if (node.object.type === 'MemberExpression' && isTaintSource(node.object)) return true;
  return false;
}

/** `req.body` / `req.query` / `req.params` — the object, not a nested property. */
export function isRequestObjectNode(node: AstNode): boolean {
  if (node.type !== 'MemberExpression') return false;
  const name = propName(node);
  return (
    node.object.type === 'Identifier' &&
    node.object.name === 'req' &&
    (name === 'body' || name === 'query' || name === 'params')
  );
}

export function isPathResolveCall(node: AstNode): boolean {
  if (node.type !== 'CallExpression') return false;
  if (node.callee.type !== 'MemberExpression') return false;
  return (
    node.callee.object.type === 'Identifier' &&
    node.callee.object.name === 'path' &&
    propName(node.callee) === 'resolve'
  );
}

export function assignedNameOf(node: AstNode): string | undefined {
  const parent = (node as unknown as NodeWithParent).parent;
  if (parent === undefined) return undefined;
  if (parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier' && parent.init === node) {
    return parent.id.name;
  }
  if (parent.type === 'AssignmentExpression' && parent.right === node) {
    if (parent.left.type === 'MemberExpression') return propName(parent.left);
    const names = boundNames(parent.left);
    return names[0];
  }
  if (
    parent.type === 'MemberExpression' ||
    parent.type === 'CallExpression' ||
    parent.type === 'BinaryExpression'
  ) {
    return assignedNameOf(parent);
  }
  return undefined;
}
