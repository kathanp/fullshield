import {
  assignedNameOf,
  attachParents,
  boundNames,
  calleeName,
  enclosingScope,
  isFunctionNode,
  isPathResolveCall,
  isRequestObjectNode,
  isTaintSource,
  propName,
  REQUEST_SOURCE_PROPS,
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
  /** Local names of functions whose return value is tainted. */
  returners: Set<string>;
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

const NO_RETURNERS: ReadonlySet<string> = new Set();

function exprIsTainted(
  node: AstNode | undefined,
  tainted: Set<string>,
  returners: ReadonlySet<string> = NO_RETURNERS,
): boolean {
  if (node === undefined) return false;
  if (isTaintSource(node)) return true;
  switch (node.type) {
    case 'Identifier':
      return tainted.has(node.name);
    case 'MemberExpression':
      return exprIsTainted(node.object, tainted, returners);
    case 'CallExpression':
      if (isSchemaValidatorCall(node)) return false;
      if (node.callee.type === 'Identifier' && returners.has(node.callee.name)) return true;
      if (node.callee.type === 'MemberExpression' && exprIsTainted(node.callee.object, tainted, returners)) {
        return true;
      }
      return node.arguments.some(
        (arg) => arg.type !== 'SpreadElement' && exprIsTainted(arg, tainted, returners),
      );
    case 'NewExpression':
      if (exprIsTainted(node.callee, tainted, returners)) return true;
      return node.arguments.some(
        (arg) => arg.type !== 'SpreadElement' && exprIsTainted(arg, tainted, returners),
      );
    case 'TemplateLiteral':
      return node.expressions.some((expr) => exprIsTainted(expr, tainted, returners));
    case 'TaggedTemplateExpression':
      return exprIsTainted(node.quasi, tainted, returners);
    case 'BinaryExpression':
      return (
        node.operator === '+' &&
        (exprIsTainted(node.left, tainted, returners) || exprIsTainted(node.right, tainted, returners))
      );
    case 'AssignmentExpression':
      return exprIsTainted(node.right, tainted, returners);
    case 'LogicalExpression':
      return exprIsTainted(node.left, tainted, returners) || exprIsTainted(node.right, tainted, returners);
    case 'ConditionalExpression':
      return (
        exprIsTainted(node.consequent, tainted, returners) ||
        exprIsTainted(node.alternate, tainted, returners)
      );
    case 'ChainExpression':
      return exprIsTainted(node.expression, tainted, returners);
    case 'TSAsExpression':
    case 'TSNonNullExpression':
    case 'TSTypeAssertion':
      return exprIsTainted(node.expression, tainted, returners);
    default:
      return false;
  }
}

function exprIsSanitized(
  node: AstNode | undefined,
  tainted: Set<string>,
  names: Set<string>,
  isCall: (n: AstNode | undefined) => boolean,
  returners: ReadonlySet<string> = NO_RETURNERS,
): boolean {
  if (node === undefined) return true;
  if (isCall(node)) return true;
  if (node.type === 'Identifier') return names.has(node.name) || !tainted.has(node.name);
  if (!exprIsTainted(node, tainted, returners)) return true;
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

function seedDestructuredRequestParams(scope: AstNode, tainted: Set<string>): void {
  if (!isFunctionNode(scope)) return;
  for (const param of scope.params) {
    if (param.type !== 'ObjectPattern') continue;
    for (const prop of param.properties) {
      if (prop.type !== 'Property') continue;
      const key = prop.key.type === 'Identifier' ? prop.key.name : undefined;
      if (key === undefined || !REQUEST_SOURCE_PROPS.has(key)) continue;
      for (const name of boundNames(prop.value)) tainted.add(name);
    }
  }
}

function analyzeScope(
  scope: AstNode,
  seed: Iterable<string> = [],
  returners: ReadonlySet<string> = NO_RETURNERS,
): ScopeFacts {
  const tainted = new Set<string>(seed);
  seedDestructuredRequestParams(scope, tainted);
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
        if (exprIsTainted(init, tainted, returners)) {
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
        if (exprIsTainted(node.right, tainted, returners)) {
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

  return {
    tainted,
    pathSanitized,
    urlSanitized,
    xssSanitized,
    hasPasswordName,
    requestObjects,
    returners: new Set(returners),
  };
}

function functionName(fn: AstNode): string | undefined {
  if (fn.type === 'FunctionDeclaration' && fn.id !== null) return fn.id.name;
  if (isFunctionNode(fn) && fn.id !== null && fn.id.type === 'Identifier') return fn.id.name;
  return assignedNameOf(fn);
}

function scopeReturnsTaint(
  scope: AstNode,
  tainted: Set<string>,
  returners: ReadonlySet<string>,
): boolean {
  let yes = false;
  walkScope(scope, (node) => {
    if (node.type === 'ReturnStatement' && node.argument !== null) {
      if (exprIsTainted(node.argument, tainted, returners)) yes = true;
    }
  });
  return yes;
}

const MAX_TAINT_HOPS = 5;

export function analyzeFile(
  ast: AstNode,
  extraReturners: ReadonlySet<string> = NO_RETURNERS,
): WeakMap<AstNode, ScopeFacts> {
  attachParents(ast);
  const facts = new WeakMap<AstNode, ScopeFacts>();
  const functions: AstNode[] = [];
  walk(ast, (node) => {
    if (isFunctionNode(node)) functions.push(node);
  });
  const nameToFn = new Map<string, AstNode>();
  for (const fn of functions) {
    const name = functionName(fn);
    if (name !== undefined) nameToFn.set(name, fn);
  }
  const seeds = new Map<AstNode, Set<string>>();
  for (const fn of functions) seeds.set(fn, new Set());
  const returners = new Set<string>(extraReturners);

  for (let hop = 0; hop < MAX_TAINT_HOPS; hop += 1) {
    let changed = false;
    facts.set(ast, analyzeScope(ast, [], returners));
    for (const fn of functions) {
      facts.set(fn, analyzeScope(fn, seeds.get(fn) ?? [], returners));
    }
    for (const fn of functions) {
      const name = functionName(fn);
      const f = facts.get(fn);
      if (name === undefined || f === undefined) continue;
      if (scopeReturnsTaint(fn, f.tainted, returners) && !returners.has(name)) {
        returners.add(name);
        changed = true;
      }
    }
    for (const fn of functions) {
      const f = facts.get(fn);
      if (f === undefined) continue;
      walkScope(fn, (node) => {
        if (node.type !== 'CallExpression') return;
        if (node.callee.type !== 'Identifier') return;
        const callee = nameToFn.get(node.callee.name);
        if (callee === undefined || !isFunctionNode(callee)) return;
        node.arguments.forEach((arg, i) => {
          if (arg.type === 'SpreadElement') return;
          if (!exprIsTainted(arg, f.tainted, returners)) return;
          const param = callee.params[i];
          if (param === undefined) return;
          const pname = boundNames(param)[0];
          if (pname === undefined) return;
          const set = seeds.get(callee) ?? new Set<string>();
          if (!set.has(pname)) {
            set.add(pname);
            seeds.set(callee, set);
            changed = true;
          }
        });
      });
    }
    if (!changed) break;
  }
  return facts;
}

export function functionsThatReturnTaint(ast: AstNode): Set<string> {
  attachParents(ast);
  const names = new Set<string>();
  const facts = analyzeFile(ast);
  walk(ast, (node) => {
    if (!isFunctionNode(node)) return;
    const name = functionName(node);
    const f = facts.get(node);
    if (name === undefined || f === undefined) return;
    if (scopeReturnsTaint(node, f.tainted, f.returners)) names.add(name);
  });
  return names;
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
      returners: new Set(),
    }
  );
}

export function nodeIsTainted(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): boolean {
  const facts = factsFor(node, map);
  return exprIsTainted(node, facts.tainted, facts.returners);
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
  if (kind === 'url') {
    return exprIsSanitized(node, facts.tainted, facts.urlSanitized, isUrlSanitizerCall, facts.returners);
  }
  return exprIsSanitized(node, facts.tainted, facts.xssSanitized, isXssSanitizerCall, facts.returners);
}

export function nodeIsRequestObject(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): boolean {
  if (isRequestObjectNode(node)) return true;
  if (node.type === 'Identifier') return factsFor(node, map).requestObjects.has(node.name);
  return false;
}
