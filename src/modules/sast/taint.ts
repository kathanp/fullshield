import {
  attachParents,
  boundNames,
  enclosingScope,
  isFunctionNode,
  isPathResolveCall,
  isRequestObjectNode,
  isTaintSource,
  propName,
  walk,
} from './ast.js';
import type { AstNode } from './types.js';

export interface ScopeFacts {
  tainted: Set<string>;
  pathSanitized: Set<string>;
  hasPasswordName: boolean;
  /** Identifiers bound to req.body/query/params themselves (not a property). */
  requestObjects: Set<string>;
}

function exprIsTainted(node: AstNode | undefined, tainted: Set<string>): boolean {
  if (node === undefined) return false;
  if (isTaintSource(node)) return true;
  switch (node.type) {
    case 'Identifier':
      return tainted.has(node.name);
    case 'MemberExpression':
      return exprIsTainted(node.object, tainted);
    case 'CallExpression':
    case 'NewExpression':
      return node.arguments.some((arg) => arg.type !== 'SpreadElement' && exprIsTainted(arg, tainted));
    case 'TemplateLiteral':
      return node.expressions.some((expr) => exprIsTainted(expr, tainted));
    case 'BinaryExpression':
      return node.operator === '+' && (exprIsTainted(node.left, tainted) || exprIsTainted(node.right, tainted));
    case 'AssignmentExpression':
      return exprIsTainted(node.right, tainted);
    case 'LogicalExpression':
      return exprIsTainted(node.left, tainted) || exprIsTainted(node.right, tainted);
    case 'ConditionalExpression':
      return exprIsTainted(node.consequent, tainted) || exprIsTainted(node.alternate, tainted);
    case 'ChainExpression':
      return exprIsTainted(node.expression, tainted);
    case 'TSAsExpression':
    case 'TSNonNullExpression':
    case 'TSTypeAssertion':
      return exprIsTainted(node.expression, tainted);
    default:
      return false;
  }
}

/** Walk a scope without descending into nested functions (taint is intra-function). */
function walkScope(scope: AstNode, visit: (n: AstNode) => void): void {
  function inner(node: AstNode): void {
    if (node !== scope && isFunctionNode(node)) return;
    visit(node);
    for (const key of Object.keys(node) as Array<keyof AstNode>) {
      if (['loc', 'range', 'type', 'parent'].includes(String(key))) continue;
      const value = node[key];
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child !== null && typeof child === 'object' && 'type' in child) {
            inner(child);
          }
        }
      } else if (value !== null && typeof value === 'object' && 'type' in value) {
        inner(value);
      }
    }
  }
  inner(scope);
}

function analyzeScope(scope: AstNode): ScopeFacts {
  const tainted = new Set<string>();
  let changed = true;
  while (changed) {
    changed = false;
    walkScope(scope, (node) => {
      if (node.type === 'VariableDeclarator' && exprIsTainted(node.init ?? undefined, tainted)) {
        for (const name of boundNames(node.id)) {
          if (!tainted.has(name)) {
            tainted.add(name);
            changed = true;
          }
        }
      }
      if (node.type === 'AssignmentExpression' && exprIsTainted(node.right, tainted)) {
        for (const name of boundNames(node.left)) {
          if (!tainted.has(name)) {
            tainted.add(name);
            changed = true;
          }
        }
      }
    });
  }

  const resolved = new Set<string>();
  walkScope(scope, (node) => {
    if (node.type === 'VariableDeclarator' && node.init !== null && isPathResolveCall(node.init)) {
      for (const name of boundNames(node.id)) resolved.add(name);
    }
    if (node.type === 'AssignmentExpression' && isPathResolveCall(node.right)) {
      for (const name of boundNames(node.left)) resolved.add(name);
    }
  });

  const pathSanitized = new Set<string>();
  walkScope(scope, (node) => {
    if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') return;
    if (propName(node.callee) !== 'startsWith') return;
    if (node.callee.object.type === 'Identifier' && resolved.has(node.callee.object.name)) {
      pathSanitized.add(node.callee.object.name);
    }
  });

  let hasPasswordName = false;
  walkScope(scope, (node) => {
    if (node.type === 'Identifier' && /password|passwd|pwd/i.test(node.name)) {
      hasPasswordName = true;
    }
  });
  if (scope.type === 'FunctionDeclaration' && scope.id !== null && /password|passwd|pwd/i.test(scope.id.name)) {
    hasPasswordName = true;
  }

  const requestObjects = new Set<string>();
  walkScope(scope, (node) => {
    if (node.type === 'VariableDeclarator' && node.init !== null && isRequestObjectNode(node.init)) {
      for (const name of boundNames(node.id)) requestObjects.add(name);
    }
    if (node.type === 'AssignmentExpression' && isRequestObjectNode(node.right)) {
      for (const name of boundNames(node.left)) requestObjects.add(name);
    }
  });

  return { tainted, pathSanitized, hasPasswordName, requestObjects };
}

export function analyzeFile(ast: AstNode): WeakMap<AstNode, ScopeFacts> {
  attachParents(ast);
  const facts = new WeakMap<AstNode, ScopeFacts>();
  facts.set(ast, analyzeScope(ast));
  walk(ast, (node) => {
    if (isFunctionNode(node)) facts.set(node, analyzeScope(node));
  });
  return facts;
}

export function factsFor(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): ScopeFacts {
  return (
    map.get(enclosingScope(node)) ?? {
      tainted: new Set(),
      pathSanitized: new Set(),
      hasPasswordName: false,
      requestObjects: new Set(),
    }
  );
}

export function nodeIsTainted(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): boolean {
  return exprIsTainted(node, factsFor(node, map).tainted);
}

export function nodeIsPathSanitized(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'Identifier') return false;
  return factsFor(node, map).pathSanitized.has(node.name);
}

export function nodeIsRequestObject(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): boolean {
  if (isRequestObjectNode(node)) return true;
  if (node.type === 'Identifier') return factsFor(node, map).requestObjects.has(node.name);
  return false;
}
