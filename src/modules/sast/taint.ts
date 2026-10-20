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
import {
  isFrameworkMemberTaint,
  isFrameworkRequestObject,
  isFrameworkTaintCall,
  nestDecoratorArgCount,
  nestInputDecorator,
} from './frameworks.js';
import { frameworksEnabled, taintV2Enabled } from './experimental.js';
import { modelSourceNode } from './models.js';
import { isMcpArgsTaintSource, isMcpToolHandler } from './mcp.js';
import type { AstNode } from './types.js';

export type SinkSanitizer = 'url' | 'xss';

export interface CustomTaintConfig {
  sources: ReadonlySet<string>;
  /** Callee name → B4 classes it clears. `secrets` and `deps` are never included. */
  sanitizers: ReadonlyMap<string, ReadonlySet<string>>;
}

let customTaint: CustomTaintConfig | undefined;

export function setCustomTaint(config: CustomTaintConfig | undefined): void {
  customTaint = config;
}

export interface ScopeFacts {
  tainted: Set<string>;
  pathSanitized: Set<string>;
  sqlCleared: Set<string>;
  urlSanitized: Set<string>;
  xssSanitized: Set<string>;
  nosqlSanitized: Set<string>;
  hasPasswordName: boolean;
  /** Identifiers bound to req.body/query/params themselves (not a property). */
  requestObjects: Set<string>;
  /** Identifiers that hold an object or array assembled from request input. */
  builtFilters: Set<string>;
  /** Same-file functions whose return value is a built Mongo filter. */
  filterReturners: Set<string>;
  /** Local names of functions whose return value is tainted. */
  returners: Set<string>;
}

const SCHEMA_ROOT = /^(z|zod|joi|yup|schema)$/i;

function objectChainMentions(node: AstNode, pattern: RegExp): boolean {
  let current: AstNode | undefined = node;
  for (let i = 0; i < 8 && current !== undefined; i += 1) {
    if (current.type === 'Identifier' && pattern.test(current.name)) {return true;}
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
  if (node === undefined || node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  if (name !== 'parse' && name !== 'validate' && name !== 'safeParse') {return false;}
  if (node.callee.type === 'MemberExpression') {
    if (node.callee.object.type === 'Identifier' && node.callee.object.name === 'JSON') {return false;}
    return objectChainMentions(node.callee.object, SCHEMA_ROOT);
  }
  return false;
}

export function isUrlSanitizerCall(node: AstNode | undefined): boolean {
  if (node === undefined || node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  return name === 'encodeURIComponent' || name === 'encodeURI';
}

export function isCoercionCall(node: AstNode | undefined): boolean {
  if (node === undefined || node.type !== 'CallExpression') {return false;}
  return node.callee.type === 'Identifier' && (node.callee.name === 'String' || node.callee.name === 'Number' || node.callee.name === 'Boolean');
}

export function isMongoSanitizeCall(node: AstNode | undefined): boolean {
  if (node === undefined || node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  return name === 'mongoSanitize' || name === 'mongo_sanitize';
}

export function isXssSanitizerCall(node: AstNode | undefined): boolean {
  if (node === undefined || node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  if (name === 'escape' || name === 'sanitize') {return true;}
  if (node.callee.type === 'MemberExpression' && node.callee.object.type === 'Identifier') {
    return /^(DOMPurify|he|validator)$/.test(node.callee.object.name) && (name === 'sanitize' || name === 'escape');
  }
  return false;
}

const NO_RETURNERS: ReadonlySet<string> = new Set();
const CALLBACK_METHODS = new Set([
  'then',
  'catch',
  'finally',
  'map',
  'forEach',
  'filter',
  'flatMap',
  'find',
  'reduce',
]);
const taintedThisFields = new WeakMap<AstNode, Set<string>>();

function enclosingClass(node: AstNode): AstNode | undefined {
  let current: AstNode | undefined = (node as { parent?: AstNode }).parent;
  while (current !== undefined) {
    if (current.type === 'ClassDeclaration' || current.type === 'ClassExpression') {return current;}
    current = (current as { parent?: AstNode }).parent;
  }
  return undefined;
}

function exprIsTainted(
  node: AstNode | undefined,
  tainted: Set<string>,
  returners: ReadonlySet<string> = NO_RETURNERS,
): boolean {
  if (node === undefined) {return false;}
  if (modelSourceNode(node)) {return true;}
  if (isTaintSource(node) || isFrameworkMemberTaint(node) || isFrameworkTaintCall(node) || isMcpArgsTaintSource(node)) {
    return true;
  }
  switch (node.type) {
    case 'AwaitExpression':
      return exprIsTainted(node.argument, tainted, returners);
    case 'Identifier':
      return tainted.has(node.name);
    case 'MemberExpression':
      if (taintV2Enabled() && node.object.type === 'ThisExpression') {
        const cls = enclosingClass(node);
        const name = propName(node);
        if (cls !== undefined && name !== undefined && taintedThisFields.get(cls)?.has(name) === true) {
          return true;
        }
      }
      return exprIsTainted(node.object, tainted, returners);
    case 'ArrayExpression':
      if (!taintV2Enabled()) {return false;}
      return node.elements.some((el) => {
        if (el === null) {return false;}
        if (el.type === 'SpreadElement') {return exprIsTainted(el.argument, tainted, returners);}
        return exprIsTainted(el, tainted, returners);
      });
    case 'ObjectExpression':
      if (!taintV2Enabled()) {return false;}
      return node.properties.some((prop) => {
        if (prop.type === 'SpreadElement') {return exprIsTainted(prop.argument, tainted, returners);}
        if (prop.type !== 'Property') {return false;}
        return exprIsTainted(prop.value, tainted, returners);
      });
    case 'CallExpression':
      if (
        taintV2Enabled() &&
        node.callee.type === 'MemberExpression' &&
        node.callee.object.type === 'Identifier' &&
        node.callee.object.name === 'Object' &&
        propName(node.callee) === 'assign'
      ) {
        return node.arguments.some(
          (arg) => arg.type !== 'SpreadElement' && exprIsTainted(arg, tainted, returners),
        );
      }
      if (isSchemaValidatorCall(node)) {return false;}
      if (node.callee.type === 'Identifier' && returners.has(node.callee.name)) {return true;}
      if (node.callee.type === 'MemberExpression' && exprIsTainted(node.callee.object, tainted, returners)) {
        return true;
      }
      return node.arguments.some(
        (arg) => arg.type !== 'SpreadElement' && exprIsTainted(arg, tainted, returners),
      );
    case 'NewExpression':
      if (exprIsTainted(node.callee, tainted, returners)) {return true;}
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

/**
 * True when this value can put request data into a Mongo filter object.
 * A bare tainted name is not itself a built filter; an object, array, or
 * Object.assign that contains one is.
 */
function valueFeedsFilter(
  node: AstNode | undefined,
  tainted: Set<string>,
  returners: ReadonlySet<string>,
  nosqlSanitized: Set<string>,
  built: Set<string>,
  filterReturners: ReadonlySet<string>,
): boolean {
  if (node === undefined) {return false;}
  if (isCoercionCall(node) || isSchemaValidatorCall(node) || isMongoSanitizeCall(node)) {return false;}
  if (node.type === 'Identifier') {
    if (nosqlSanitized.has(node.name)) {return false;}
    return built.has(node.name) || tainted.has(node.name);
  }
  if (isRequestObjectNode(node)) {return true;}
  if (node.type === 'AwaitExpression') {
    return valueFeedsFilter(node.argument, tainted, returners, nosqlSanitized, built, filterReturners);
  }
  if (
    node.type === 'CallExpression' &&
    node.callee.type === 'Identifier' &&
    filterReturners.has(node.callee.name)
  ) {
    return true;
  }
  if (node.type === 'ObjectExpression') {
    return node.properties.some((prop) => {
      if (prop.type === 'SpreadElement') {
        return valueFeedsFilter(prop.argument, tainted, returners, nosqlSanitized, built, filterReturners);
      }
      if (prop.type !== 'Property') {return false;}
      return valueFeedsFilter(prop.value, tainted, returners, nosqlSanitized, built, filterReturners);
    });
  }
  if (node.type === 'ArrayExpression') {
    return node.elements.some((el) => {
      if (el === null) {return false;}
      if (el.type === 'SpreadElement') {
        return valueFeedsFilter(el.argument, tainted, returners, nosqlSanitized, built, filterReturners);
      }
      return valueFeedsFilter(el, tainted, returners, nosqlSanitized, built, filterReturners);
    });
  }
  if (
    node.type === 'CallExpression' &&
    node.callee.type === 'MemberExpression' &&
    node.callee.object.type === 'Identifier' &&
    node.callee.object.name === 'Object' &&
    propName(node.callee) === 'assign'
  ) {
    return node.arguments.some(
      (arg) =>
        arg.type !== 'SpreadElement' &&
        valueFeedsFilter(arg, tainted, returners, nosqlSanitized, built, filterReturners),
    );
  }
  if (
    node.type === 'ChainExpression' ||
    node.type === 'TSAsExpression' ||
    node.type === 'TSNonNullExpression' ||
    node.type === 'TSTypeAssertion' ||
    node.type === 'MemberExpression'
  ) {
    return exprIsTainted(node, tainted, returners);
  }
  return false;
}

function initIsBuiltFilter(
  node: AstNode,
  tainted: Set<string>,
  returners: ReadonlySet<string>,
  nosqlSanitized: Set<string>,
  built: Set<string>,
  filterReturners: ReadonlySet<string>,
): boolean {
  if (node.type === 'AwaitExpression') {
    return initIsBuiltFilter(node.argument, tainted, returners, nosqlSanitized, built, filterReturners);
  }
  if (node.type === 'Identifier') {return built.has(node.name) && !nosqlSanitized.has(node.name);}
  if (
    node.type === 'CallExpression' &&
    node.callee.type === 'Identifier' &&
    filterReturners.has(node.callee.name)
  ) {
    return true;
  }
  if (node.type === 'ObjectExpression' || node.type === 'ArrayExpression') {
    return valueFeedsFilter(node, tainted, returners, nosqlSanitized, built, filterReturners);
  }
  return (
    node.type === 'CallExpression' &&
    node.callee.type === 'MemberExpression' &&
    node.callee.object.type === 'Identifier' &&
    node.callee.object.name === 'Object' &&
    propName(node.callee) === 'assign' &&
    valueFeedsFilter(node, tainted, returners, nosqlSanitized, built, filterReturners)
  );
}

function exprIsSanitized(
  node: AstNode | undefined,
  tainted: Set<string>,
  names: Set<string>,
  isCall: (n: AstNode | undefined) => boolean,
  returners: ReadonlySet<string> = NO_RETURNERS,
): boolean {
  if (node === undefined) {return true;}
  if (isCall(node)) {return true;}
  if (node.type === 'Identifier') {return names.has(node.name) || !tainted.has(node.name);}
  if (!exprIsTainted(node, tainted, returners)) {return true;}
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
    if (node !== scope && isFunctionNode(node)) {return;}
    visit(node);
    for (const key of Object.keys(node) as Array<keyof AstNode>) {
      if (['loc', 'range', 'type', 'parent'].includes(String(key))) {continue;}
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
  if (!isFunctionNode(scope)) {return;}
  for (const param of scope.params) {
    if (param.type !== 'ObjectPattern') {continue;}
    for (const prop of param.properties) {
      if (prop.type !== 'Property') {continue;}
      const key = prop.key.type === 'Identifier' ? prop.key.name : undefined;
      if (key === undefined || !REQUEST_SOURCE_PROPS.has(key)) {continue;}
      for (const name of boundNames(prop.value)) {tainted.add(name);}
    }
  }
}

function seedFrameworkParams(scope: AstNode, tainted: Set<string>): void {
  if (!frameworksEnabled() || !isFunctionNode(scope)) {return;}
  for (const param of scope.params) {
    if (param.type === 'Identifier' && param.name === 'formData') {tainted.add('formData');}
    const nest = nestInputDecorator(param);
    if (nest === undefined) {continue;}
    for (const name of boundNames(param)) {tainted.add(name);}
  }
}

function seedMcpToolParams(scope: AstNode, tainted: Set<string>): void {
  if (!isFunctionNode(scope) || !isMcpToolHandler(scope)) {return;}
  for (const param of scope.params) {
    for (const name of boundNames(param)) {tainted.add(name);}
  }
}

function analyzeScope(
  scope: AstNode,
  seed: Iterable<string> = [],
  returners: ReadonlySet<string> = NO_RETURNERS,
  filterReturners: ReadonlySet<string> = NO_RETURNERS,
  initialBuilt: ReadonlySet<string> = NO_RETURNERS,
): ScopeFacts {
  const tainted = new Set<string>(seed);
  seedDestructuredRequestParams(scope, tainted);
  seedFrameworkParams(scope, tainted);
  seedMcpToolParams(scope, tainted);
  const urlSanitized = new Set<string>();
  const xssSanitized = new Set<string>();
  const nosqlSanitized = new Set<string>();
  const sqlCleared = new Set<string>();
  const customPath = new Set<string>();
  let changed = true;
  while (changed) {
    changed = false;
    walkScope(scope, (node) => {
      if (node.type === 'VariableDeclarator') {
        const init = node.init ?? undefined;
        if (isSchemaValidatorCall(init) || isCoercionCall(init) || isMongoSanitizeCall(init)) {
          for (const name of boundNames(node.id)) {nosqlSanitized.add(name);}
        }
        if (isSchemaValidatorCall(init)) {return;}
        applyCustomCall(init, boundNames(node.id), tainted, sqlCleared, customPath);
        if (isUrlSanitizerCall(init)) {
          for (const name of boundNames(node.id)) {urlSanitized.add(name);}
        }
        if (isXssSanitizerCall(init)) {
          for (const name of boundNames(node.id)) {xssSanitized.add(name);}
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
        if (isSchemaValidatorCall(node.right) || isCoercionCall(node.right) || isMongoSanitizeCall(node.right)) {
          for (const name of boundNames(node.left)) {nosqlSanitized.add(name);}
        }
        if (isSchemaValidatorCall(node.right)) {return;}
        applyCustomCall(node.right, boundNames(node.left), tainted, sqlCleared, customPath);
        if (isUrlSanitizerCall(node.right)) {
          for (const name of boundNames(node.left)) {urlSanitized.add(name);}
        }
        if (isXssSanitizerCall(node.right)) {
          for (const name of boundNames(node.left)) {xssSanitized.add(name);}
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
      for (const name of boundNames(node.id)) {resolved.add(name);}
    }
    if (node.type === 'AssignmentExpression' && isPathResolveCall(node.right)) {
      for (const name of boundNames(node.left)) {resolved.add(name);}
    }
  });

  const pathSanitized = new Set<string>(customPath);
  walkScope(scope, (node) => {
    if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return;}
    if (propName(node.callee) !== 'startsWith') {return;}
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
  if (frameworksEnabled() && isFunctionNode(scope)) {
    for (const param of scope.params) {
      const nest = nestInputDecorator(param);
      if (nest === 'Body' || nest === 'Query' || nest === 'Param') {
        if (nestDecoratorArgCount(param, nest) === 0) {
          for (const name of boundNames(param)) {requestObjects.add(name);}
        }
      }
    }
  }
  walkScope(scope, (node) => {
    if (node.type === 'VariableDeclarator' && node.init !== null && isRequestObjectNode(node.init)) {
      for (const name of boundNames(node.id)) {requestObjects.add(name);}
    }
    if (node.type === 'AssignmentExpression' && isRequestObjectNode(node.right)) {
      for (const name of boundNames(node.left)) {requestObjects.add(name);}
    }
    if (node.type === 'VariableDeclarator' && node.init !== null && isFrameworkRequestObject(node.init)) {
      for (const name of boundNames(node.id)) {requestObjects.add(name);}
    }
    if (node.type === 'AssignmentExpression' && isFrameworkRequestObject(node.right)) {
      for (const name of boundNames(node.left)) {requestObjects.add(name);}
    }
  });

  const builtFilters = new Set<string>(initialBuilt);
  let grew = true;
  while (grew) {
    grew = false;
    const add = (names: readonly string[]): void => {
      for (const name of names) {
        if (nosqlSanitized.has(name) || builtFilters.has(name)) {continue;}
        builtFilters.add(name);
        grew = true;
      }
    };
    walkScope(scope, (node) => {
      if (node.type === 'VariableDeclarator' && node.init !== null) {
        if (initIsBuiltFilter(node.init, tainted, returners, nosqlSanitized, builtFilters, filterReturners)) {
          add(boundNames(node.id));
        }
      }
      if (node.type !== 'AssignmentExpression') {return;}
      if (
        node.left.type === 'Identifier' &&
        initIsBuiltFilter(node.right, tainted, returners, nosqlSanitized, builtFilters, filterReturners)
      ) {
        add([node.left.name]);
      }
      if (
        node.left.type === 'MemberExpression' &&
        node.left.object.type === 'Identifier' &&
        valueFeedsFilter(node.right, tainted, returners, nosqlSanitized, builtFilters, filterReturners)
      ) {
        add([node.left.object.name]);
      }
    });
  }

  return {
    tainted,
    pathSanitized,
    sqlCleared,
    urlSanitized,
    xssSanitized,
    nosqlSanitized,
    hasPasswordName,
    requestObjects,
    builtFilters,
    filterReturners: new Set(filterReturners),
    returners: new Set(returners),
  };
}

function locallyDeclared(scope: AstNode): Set<string> {
  const names = new Set<string>();
  if (isFunctionNode(scope)) {
    for (const param of scope.params) {
      for (const name of boundNames(param)) {names.add(name);}
    }
  }
  walkScope(scope, (node) => {
    if (node.type === 'VariableDeclarator') {
      for (const name of boundNames(node.id)) {names.add(name);}
    }
    if (node.type === 'FunctionDeclaration' && node.id !== null) {names.add(node.id.name);}
  });
  return names;
}

function inheritedBuiltFilters(fn: AstNode, facts: WeakMap<AstNode, ScopeFacts>): Set<string> {
  const local = locallyDeclared(fn);
  const inherited = new Set<string>();
  let parent: AstNode | undefined = (fn as { parent?: AstNode }).parent;
  while (parent !== undefined && !isFunctionNode(parent)) {
    parent = (parent as { parent?: AstNode }).parent;
  }
  const outer = parent === undefined ? undefined : facts.get(parent);
  if (outer === undefined) {return inherited;}
  for (const name of outer.builtFilters) {
    if (!local.has(name)) {inherited.add(name);}
  }
  return inherited;
}

function scopeReturnsBuiltFilter(scope: AstNode, facts: ScopeFacts): boolean {
  let yes = false;
  walkScope(scope, (node) => {
    if (node.type !== 'ReturnStatement' || node.argument === null) {return;}
    if (
      initIsBuiltFilter(
        node.argument,
        facts.tainted,
        facts.returners,
        facts.nosqlSanitized,
        facts.builtFilters,
        facts.filterReturners,
      )
    ) {
      yes = true;
    }
  });
  return yes;
}

function functionName(fn: AstNode): string | undefined {
  if (fn.type === 'FunctionDeclaration' && fn.id !== null) {return fn.id.name;}
  if (isFunctionNode(fn) && fn.id !== null && fn.id.type === 'Identifier') {return fn.id.name;}
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
      if (exprIsTainted(node.argument, tainted, returners)) {yes = true;}
    }
  });
  return yes;
}

export const MAX_TAINT_HOPS = 5;

function seedTaintV2(
  functions: AstNode[],
  facts: WeakMap<AstNode, ScopeFacts>,
  seeds: Map<AstNode, Set<string>>,
  returners: ReadonlySet<string>,
  nameToFn: Map<string, AstNode>,
): boolean {
  let changed = false;
  const mark = (fn: AstNode, name: string | undefined): void => {
    if (name === undefined) {return;}
    const set = seeds.get(fn) ?? new Set<string>();
    if (set.has(name)) {return;}
    set.add(name);
    seeds.set(fn, set);
    changed = true;
  };
  for (const fn of functions) {
    const f = facts.get(fn);
    if (f === undefined) {continue;}
    let parent: AstNode | undefined = (fn as { parent?: AstNode }).parent;
    while (parent !== undefined && !isFunctionNode(parent)) {
      parent = (parent as { parent?: AstNode }).parent;
    }
    if (parent !== undefined && isFunctionNode(parent)) {
      const outer = facts.get(parent);
      if (outer !== undefined) {
        for (const name of outer.tainted) {mark(fn, name);}
      }
    }
    walkScope(fn, (node) => {
      if (node.type === 'AssignmentExpression' && node.left.type === 'MemberExpression') {
        if (node.left.object.type === 'ThisExpression' && exprIsTainted(node.right, f.tainted, returners)) {
          const cls = enclosingClass(node);
          const field = propName(node.left);
          if (cls !== undefined && field !== undefined) {
            const fields = taintedThisFields.get(cls) ?? new Set<string>();
            if (!fields.has(field)) {
              fields.add(field);
              taintedThisFields.set(cls, fields);
              changed = true;
            }
          }
        }
      }
      if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return;}
      const method = propName(node.callee);
      if (method === undefined) {return;}
      if (CALLBACK_METHODS.has(method) && exprIsTainted(node.callee.object, f.tainted, returners)) {
        const callback = node.arguments[0];
        if (callback !== undefined && isFunctionNode(callback)) {
          mark(callback, boundNames(callback.params[0])[0]);
        }
      }
      if ((method === 'call' || method === 'apply') && node.callee.object.type === 'Identifier') {
        const target = nameToFn.get(node.callee.object.name);
        if (target === undefined || !isFunctionNode(target)) {return;}
        const arg = node.arguments[1];
        if (arg !== undefined && arg.type !== 'SpreadElement' && exprIsTainted(arg, f.tainted, returners)) {
          mark(target, boundNames(target.params[0])[0]);
        }
      }
    });
  }
  return changed;
}

export function analyzeFile(
  ast: AstNode,
  extraReturners: ReadonlySet<string> = NO_RETURNERS,
): WeakMap<AstNode, ScopeFacts> {
  attachParents(ast);
  const facts = new WeakMap<AstNode, ScopeFacts>();
  const functions: AstNode[] = [];
  walk(ast, (node) => {
    if (isFunctionNode(node)) {functions.push(node);}
  });
  const nameToFn = new Map<string, AstNode>();
  for (const fn of functions) {
    const name = functionName(fn);
    if (name !== undefined) {nameToFn.set(name, fn);}
  }
  const seeds = new Map<AstNode, Set<string>>();
  for (const fn of functions) {seeds.set(fn, new Set());}
  const returners = new Set<string>(extraReturners);
  const filterReturners = new Set<string>();

  for (let hop = 0; hop < MAX_TAINT_HOPS; hop += 1) {
    let changed = false;
    facts.set(ast, analyzeScope(ast, [], returners, filterReturners));
    for (const fn of functions) {
      facts.set(fn, analyzeScope(fn, seeds.get(fn) ?? [], returners, filterReturners, inheritedBuiltFilters(fn, facts)));
    }
    for (const fn of functions) {
      const name = functionName(fn);
      const f = facts.get(fn);
      if (name === undefined || f === undefined) {continue;}
      if (scopeReturnsTaint(fn, f.tainted, returners) && !returners.has(name)) {
        returners.add(name);
        changed = true;
      }
      if (scopeReturnsBuiltFilter(fn, f) && !filterReturners.has(name)) {
        filterReturners.add(name);
        changed = true;
      }
    }
    for (const fn of functions) {
      const f = facts.get(fn);
      if (f === undefined) {continue;}
      walkScope(fn, (node) => {
        if (node.type !== 'CallExpression') {return;}
        if (node.callee.type !== 'Identifier') {return;}
        const callee = nameToFn.get(node.callee.name);
        if (callee === undefined || !isFunctionNode(callee)) {return;}
        node.arguments.forEach((arg, i) => {
          if (arg.type === 'SpreadElement') {return;}
          if (!exprIsTainted(arg, f.tainted, returners)) {return;}
          const param = callee.params[i];
          if (param === undefined) {return;}
          const pname = boundNames(param)[0];
          if (pname === undefined) {return;}
          const set = seeds.get(callee) ?? new Set<string>();
          if (!set.has(pname)) {
            set.add(pname);
            seeds.set(callee, set);
            changed = true;
          }
        });
      });
    }
    if (taintV2Enabled() && seedTaintV2(functions, facts, seeds, returners, nameToFn)) {
      changed = true;
    }
    if (!changed) {break;}
  }
  return facts;
}

export interface FunctionTaintSummary {
  name: string;
  line: number;
  paramsToReturn: number[];
  sinks: Array<{ param: number; class: string }>;
}

const SQL_SINK_NAMES = new Set(['query', 'execute']);
const CMD_SINK_NAMES = new Set(['exec', 'execSync', 'spawn', 'spawnSync']);
const PATH_SINK_NAMES = new Set(['readFile', 'readFileSync', 'writeFile', 'writeFileSync']);

function sinkClasses(scope: AstNode, tainted: Set<string>, returners: ReadonlySet<string>): string[] {
  const found = new Set<string>();
  walkScope(scope, (node) => {
    if (node.type !== 'CallExpression') {return;}
    const name = calleeName(node);
    const first = node.arguments[0];
    if (name === undefined || first === undefined || first.type === 'SpreadElement') {return;}
    if (!exprIsTainted(first, tainted, returners)) {return;}
    if (SQL_SINK_NAMES.has(name)) {found.add('sqli');}
    if (CMD_SINK_NAMES.has(name)) {found.add('cmdi');}
    if (PATH_SINK_NAMES.has(name)) {found.add('path');}
  });
  return [...found].sort();
}

/** Same returner set as `functionsThatReturnTaint`, plus which params reach a return or a sink. */
export function fileTaintSummary(ast: AstNode): { returnsTaint: string[]; functions: FunctionTaintSummary[] } {
  attachParents(ast);
  const facts = analyzeFile(ast);
  const returnsTaint: string[] = [];
  const functions: FunctionTaintSummary[] = [];
  walk(ast, (node) => {
    if (!isFunctionNode(node)) {return;}
    const name = functionName(node);
    const own = facts.get(node);
    if (name === undefined || own === undefined) {return;}
    if (scopeReturnsTaint(node, own.tainted, own.returners)) {returnsTaint.push(name);}
    const paramsToReturn: number[] = [];
    const sinks: Array<{ param: number; class: string }> = [];
    node.params.forEach((param, index) => {
      const pname = boundNames(param)[0];
      if (pname === undefined) {return;}
      const seeded = analyzeScope(node, [pname]);
      if (scopeReturnsTaint(node, seeded.tainted, seeded.returners)) {paramsToReturn.push(index);}
      for (const cls of sinkClasses(node, seeded.tainted, seeded.returners)) {sinks.push({ param: index, class: cls });}
    });
    functions.push({
      name,
      line: node.loc?.start.line ?? 0,
      paramsToReturn,
      sinks,
    });
  });
  returnsTaint.sort();
  functions.sort((a, b) => a.line - b.line || a.name.localeCompare(b.name));
  return { returnsTaint, functions };
}

export function functionsThatReturnTaint(ast: AstNode): Set<string> {
  attachParents(ast);
  const names = new Set<string>();
  const facts = analyzeFile(ast);
  walk(ast, (node) => {
    if (!isFunctionNode(node)) {return;}
    const name = functionName(node);
    const f = facts.get(node);
    if (name === undefined || f === undefined) {return;}
    if (scopeReturnsTaint(node, f.tainted, f.returners)) {names.add(name);}
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
      sqlCleared: new Set(),
      urlSanitized: new Set(),
      xssSanitized: new Set(),
      nosqlSanitized: new Set(),
      hasPasswordName: false,
      requestObjects: new Set(),
      builtFilters: new Set(),
      filterReturners: new Set(),
      returners: new Set(),
    }
  );
}

export function nodeHoldsBuiltFilter(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): boolean {
  const facts = factsFor(node, map);
  if (node.type === 'Identifier') {return facts.builtFilters.has(node.name);}
  if (node.type === 'AwaitExpression') {return nodeHoldsBuiltFilter(node.argument, map);}
  if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
    return facts.filterReturners.has(node.callee.name);
  }
  return false;
}

export function nodeIsTainted(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): boolean {
  const facts = factsFor(node, map);
  return exprIsTainted(node, facts.tainted, facts.returners);
}

export function nodeIsSqlCleared(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type === 'Identifier') {return factsFor(node, map).sqlCleared.has(node.name);}
  return false;
}

function applyCustomCall(
  init: AstNode | undefined,
  names: readonly string[],
  tainted: Set<string>,
  sqlCleared: Set<string>,
  customPath: Set<string>,
): void {
  if (customTaint === undefined || init === undefined || init.type !== 'CallExpression') {return;}
  const called = calleeName(init);
  if (called === undefined) {return;}
  if (customTaint.sources.has(called)) {
    for (const name of names) {tainted.add(name);}
  }
  const clears = customTaint.sanitizers.get(called);
  if (clears === undefined) {return;}
  if (clears.has('sqli')) {
    for (const name of names) {sqlCleared.add(name);}
  }
  if (clears.has('path')) {
    for (const name of names) {customPath.add(name);}
  }
}

export function nodeIsPathSanitized(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): boolean {
  if (node.type !== 'Identifier') {return false;}
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
  if (isRequestObjectNode(node) || isFrameworkRequestObject(node)) {return true;}
  if (node.type === 'Identifier') {return factsFor(node, map).requestObjects.has(node.name);}
  return false;
}

export function nodeIsNosqlSanitized(node: AstNode, map: WeakMap<AstNode, ScopeFacts>): boolean {
  if (isCoercionCall(node) || isSchemaValidatorCall(node) || isMongoSanitizeCall(node)) {return true;}
  if (node.type === 'Identifier') {return factsFor(node, map).nosqlSanitized.has(node.name);}
  return false;
}
