import {
  attachParents,
  boundNames,
  calleeName,
  enclosingScope,
  isFunctionNode,
  isPathResolveCall,
  isRequestObjectNode,
  isTaintSource,
  propName,
  walk,
} from './ast.js';
import type { AstNode } from './types.js';

export type SinkSanitizer = 'url' | 'xss';

export interface ScopeFacts {
  tainted: Set<string>;
  pathSanitized: Set<string>;
  urlSanitized: Set<string>;
  xssSanitized: Set<string>;
  hasPasswordName: boolean;
  /** Identifiers bound to req.body/query/params themselves (not a property). */
  requestObjects: Set<string>;
}

const SCHEMA_ROOT = /^(z|zod|joi|yup|schema)$/i;

function objectChainMentions(node: AstNode, pattern: RegExp): boolean {
  let current: AstNode | undefined = node;
  for (let i = 0; i < 8 && current !== undefined; i += 1) {
    if (current.type === 'Identifier' && pattern.test(current.name)) return true;
    if (current.type === 'CallExpression') {
      current = current.callee;
      continue;
    }
    if (current.type === 'MemberExpression') {
      current = current.object;
      continue;
    }
    break;
  }
  return false;
}

/** zod / joi / yup `.parse()` / `.validate()` only — never JSON.parse or a bare parse(). */
export function isSchemaValidatorCall(node: AstNode | undefined): boolean {
  if (node === undefined || node.type !== 'CallExpression') return false;
  const name = calleeName(node);
  if (name !== 'parse' && name !== 'validate' && name !== 'safeParse') return false;
  if (node.callee.type === 'MemberExpression') {
    if (node.callee.object.type === 'Identifier' && node.callee.object.name === 'JSON') return false;
    return objectChainMentions(node.callee.object, SCHEMA_ROOT);
  }
  return false;
}

export function isUrlSanitizerCall(node: AstNode | undefined): boolean {
  if (node === undefined || node.type !== 'CallExpression') return false;
  const name = calleeName(node);
  return name === 'encodeURIComponent' || name === 'encodeURI';
}

export function isXssSanitizerCall(node: AstNode | undefined): boolean {
  if (node === undefined || node.type !== 'CallExpression') return false;
  const name = calleeName(node);
  if (name === 'escape' || name === 'sanitize') return true;
  if (node.callee.type === 'MemberExpression' && node.callee.object.type === 'Identifier') {
    return /^(DOMPurify|he|validator)$/.test(node.callee.object.name) && (name === 'sanitize' || name === 'escape');
  }
  return false;
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
      if (isSchemaValidatorCall(node)) return false;
      return node.arguments.some((arg) => arg.type !== 'SpreadElement' && exprIsTainted(arg, tainted));
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

function exprIsSanitized(
  node: AstNode | undefined,
  tainted: Set<string>,
  names: Set<string>,
  isCall: (n: AstNode | undefined) => boolean,
): boolean {
  if (node === undefined) return true;
  if (isCall(node)) return true;
  if (node.type === 'Identifier') return names.has(node.name) || !tainted.has(node.name);
  if (!exprIsTainted(node, tainted)) return true;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return (
      exprIsSanitized(node.left, tainted, names, isCall) &&
      exprIsSanitized(node.right, tainted, names, isCall)
    );
  }
  if (node.type === 'TemplateLiteral') {
    return node.expressions.every((expr) => exprIsSanitized(expr, tainted, names, isCall));
  }
  if (node.type === 'ConditionalExpression') {
    return (
      exprIsSanitized(node.consequent, tainted, names, isCall) &&
      exprIsSanitized(node.alternate, tainted, names, isCall)
    );
  }
  return false;
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

function analyzeScope(scope: AstNode, seed: Iterable<string> = []): ScopeFacts {
  const tainted = new Set<string>(seed);
  const urlSanitized = new Set<string>();
  const xssSanitized = new Set<string>();
  let changed = true;
  while (changed) {
    changed = false;
    walkScope(scope, (node) => {
      if (node.type === 'VariableDeclarator') {
        const init = node.init ?? undefined;
        if (isSchemaValidatorCall(init)) return;
        if (isUrlSanitizerCall(init)) {
          for (const name of boundNames(node.id)) urlSanitized.add(name);
        }
        if (isXssSanitizerCall(init)) {
          for (const name of boundNames(node.id)) xssSanitized.add(name);
        }
        if (exprIsTainted(init, tainted)) {
          for (const name of boundNames(node.id)) {
            if (!tainted.has(name)) {
              tainted.add(name);
              changed = true;
            }
          }
        }
      }
      if (node.type === 'AssignmentExpression') {
        if (isSchemaValidatorCall(node.right)) return;
        if (isUrlSanitizerCall(node.right)) {
          for (const name of boundNames(node.left)) urlSanitized.add(name);
        }
        if (isXssSanitizerCall(node.right)) {
          for (const name of boundNames(node.left)) xssSanitized.add(name);
        }
        if (exprIsTainted(node.right, tainted)) {
          for (const name of boundNames(node.left)) {
            if (!tainted.has(name)) {
              tainted.add(name);
              changed = true;
            }
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

  return { tainted, pathSanitized, urlSanitized, xssSanitized, hasPasswordName, requestObjects };
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

/** Analyze one function with extra tainted names (cross-file parameter taint). */
export function analyzeFunctionWithSeed(fn: AstNode, seed: Iterable<string>): ScopeFacts {
  attachParents(fn);
  return analyzeScope(fn, seed);
}

export { exprIsTainted };

export function factsFor(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): ScopeFacts {
  return (
    map.get(enclosingScope(node)) ?? {
      tainted: new Set(),
      pathSanitized: new Set(),
      urlSanitized: new Set(),
      xssSanitized: new Set(),
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

export function nodeIsSanitizedFor(
  node: AstNode,
  map: WeakMap<AstNode, ScopeFacts>,
  kind: SinkSanitizer,
): boolean {
  const facts = factsFor(node, map);
  if (kind === 'url') return exprIsSanitized(node, facts.tainted, facts.urlSanitized, isUrlSanitizerCall);
  return exprIsSanitized(node, facts.tainted, facts.xssSanitized, isXssSanitizerCall);
}

export function nodeIsRequestObject(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): boolean {
  if (isRequestObjectNode(node)) return true;
  if (node.type === 'Identifier') return factsFor(node, map).requestObjects.has(node.name);
  return false;
}
