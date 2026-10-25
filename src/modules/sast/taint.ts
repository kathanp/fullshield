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
const flow2LocalTaint = new WeakMap<AstNode, ReadonlySet<string>>();
const flow2FieldLine = new WeakMap<Set<string>, Map<string, number>>();
let flow2Active = false;

type Flow2Seed = (functions: readonly AstNode[], seeds: Map<AstNode, Set<string>>) => boolean;
let flow2Seed: Flow2Seed | undefined;

/** Phase 502. The flow2 module calls these. Flag off leaves them unset, so that module is not loaded. */
export function setFlow2Active(on: boolean): void {
  flow2Active = on;
}

export function setFlow2Seed(fn: Flow2Seed | undefined): void {
  flow2Seed = fn;
}

export function flow2LocalTaintOf(fn: AstNode): ReadonlySet<string> {
  return flow2LocalTaint.get(fn) ?? NO_RETURNERS;
}

function enclosingClass(node: AstNode): AstNode | undefined {
  let current: AstNode | undefined = (node as { parent?: AstNode }).parent;
  while (current !== undefined) {
    if (current.type === 'ClassDeclaration' || current.type === 'ClassExpression') {return current;}
    current = (current as { parent?: AstNode }).parent;
  }
  return undefined;
}

function startLine(node: AstNode): number | undefined {
  return (node as { loc?: { start?: { line?: number } } }).loc?.start?.line;
}

function isProcessArgv(node: AstNode): boolean {
  return (
    node.type === 'MemberExpression' &&
    node.object.type === 'Identifier' &&
    node.object.name === 'process' &&
    propName(node) === 'argv'
  );
}

function isArgvSource(node: AstNode): boolean {
  if (isProcessArgv(node)) {return true;}
  return node.type === 'MemberExpression' && isArgvSource(node.object);
}

/** True when every taint source in the expression is process.argv or a name bound from it. */
function exprIsArgvDerived(node: AstNode | undefined, argvNames: ReadonlySet<string>): boolean {
  if (node === undefined) {return false;}
  let argv = false;
  let request = false;
  walk(node, (current) => {
    if (isArgvSource(current)) {argv = true;}
    else if (current.type === 'Identifier' && argvNames.has(current.name)) {argv = true;}
    else if (isTaintSource(current)) {request = true;}
  });
  return argv && !request;
}

function fieldLines(tainted: Set<string>): Map<string, number> {
  const existing = flow2FieldLine.get(tainted);
  if (existing !== undefined) {return existing;}
  const created = new Map<string, number>();
  flow2FieldLine.set(tainted, created);
  return created;
}

/** A flow2 field counts only on a read after the assignment. A seeded key has no line. */
function flow2FieldHit(node: AstNode, tainted: Set<string>): boolean {
  if (!flow2Active || node.type !== 'MemberExpression') {return false;}
  if (node.object.type !== 'Identifier' || node.computed === true) {return false;}
  const field = propName(node);
  if (field === undefined) {return false;}
  const key = `${node.object.name}.${field}`;
  if (!tainted.has(key)) {return false;}
  const assigned = flow2FieldLine.get(tainted)?.get(key);
  if (assigned === undefined) {return true;}
  const line = startLine(node);
  return line === undefined || line > assigned;
}

function memberIsTainted(node: AstNode, tainted: Set<string>, returners: ReadonlySet<string>): boolean {
  if (node.type !== 'MemberExpression') {return false;}
  if (flow2FieldHit(node, tainted)) {return true;}
  if (taintV2Enabled() && node.object.type === 'ThisExpression') {
    const cls = enclosingClass(node);
    const name = propName(node);
    if (cls !== undefined && name !== undefined && taintedThisFields.get(cls)?.has(name) === true) {return true;}
  }
  return exprIsTainted(node.object, tainted, returners);
}

function objectAssignTainted(node: AstNode, tainted: Set<string>, returners: ReadonlySet<string>): boolean {
  return (
    taintV2Enabled() &&
    node.type === 'CallExpression' &&
    node.callee.type === 'MemberExpression' &&
    node.callee.object.type === 'Identifier' &&
    node.callee.object.name === 'Object' &&
    propName(node.callee) === 'assign' &&
    node.arguments.some((arg) => arg.type !== 'SpreadElement' && exprIsTainted(arg, tainted, returners))
  );
}

function callIsTainted(node: AstNode, tainted: Set<string>, returners: ReadonlySet<string>): boolean {
  if (node.type === 'NewExpression') {
    if (exprIsTainted(node.callee, tainted, returners)) {return true;}
    return node.arguments.some((arg) => arg.type !== 'SpreadElement' && exprIsTainted(arg, tainted, returners));
  }
  if (node.type !== 'CallExpression') {return false;}
  if (objectAssignTainted(node, tainted, returners)) {return true;}
  if (isSchemaValidatorCall(node)) {return false;}
  if (node.callee.type === 'Identifier' && returners.has(node.callee.name)) {return true;}
  if (node.callee.type === 'MemberExpression' && exprIsTainted(node.callee.object, tainted, returners)) {return true;}
  return node.arguments.some((arg) => arg.type !== 'SpreadElement' && exprIsTainted(arg, tainted, returners));
}

function elementIsTainted(el: AstNode | null, tainted: Set<string>, returners: ReadonlySet<string>): boolean {
  if (el === null) {return false;}
  if (el.type === 'SpreadElement') {return exprIsTainted(el.argument, tainted, returners);}
  return exprIsTainted(el, tainted, returners);
}

function propertyIsTainted(prop: AstNode, tainted: Set<string>, returners: ReadonlySet<string>): boolean {
  if (prop.type === 'SpreadElement') {return exprIsTainted(prop.argument, tainted, returners);}
  if (prop.type !== 'Property') {return false;}
  return exprIsTainted(prop.value, tainted, returners);
}

function collectionIsTainted(node: AstNode, tainted: Set<string>, returners: ReadonlySet<string>): boolean {
  if (!taintV2Enabled()) {return false;}
  if (node.type === 'ArrayExpression') {return node.elements.some((el) => elementIsTainted(el, tainted, returners));}
  if (node.type !== 'ObjectExpression') {return false;}
  return node.properties.some((prop) => propertyIsTainted(prop, tainted, returners));
}

function binaryIsTainted(node: AstNode, tainted: Set<string>, returners: ReadonlySet<string>): boolean {
  if (node.type === 'BinaryExpression') {
    return node.operator === '+' && (exprIsTainted(node.left, tainted, returners) || exprIsTainted(node.right, tainted, returners));
  }
  if (node.type === 'LogicalExpression') {
    return exprIsTainted(node.left, tainted, returners) || exprIsTainted(node.right, tainted, returners);
  }
  if (node.type !== 'ConditionalExpression') {return false;}
  return exprIsTainted(node.consequent, tainted, returners) || exprIsTainted(node.alternate, tainted, returners);
}

function isBinaryShape(node: AstNode): boolean {
  return node.type === 'BinaryExpression' || node.type === 'LogicalExpression' || node.type === 'ConditionalExpression';
}

function assertionExpr(node: AstNode): AstNode | undefined {
  if (
    node.type === 'ChainExpression' ||
    node.type === 'TSAsExpression' ||
    node.type === 'TSNonNullExpression' ||
    node.type === 'TSTypeAssertion'
  ) {
    return node.expression;
  }
  return undefined;
}

function shapeIsTainted(node: AstNode, tainted: Set<string>, returners: ReadonlySet<string>): boolean {
  if (node.type === 'AwaitExpression') {return exprIsTainted(node.argument, tainted, returners);}
  if (node.type === 'Identifier') {return tainted.has(node.name);}
  if (node.type === 'MemberExpression') {return memberIsTainted(node, tainted, returners);}
  if (node.type === 'CallExpression' || node.type === 'NewExpression') {return callIsTainted(node, tainted, returners);}
  if (node.type === 'ArrayExpression' || node.type === 'ObjectExpression') {return collectionIsTainted(node, tainted, returners);}
  if (node.type === 'TemplateLiteral') {return node.expressions.some((expr) => exprIsTainted(expr, tainted, returners));}
  if (node.type === 'TaggedTemplateExpression') {return exprIsTainted(node.quasi, tainted, returners);}
  if (node.type === 'AssignmentExpression') {return exprIsTainted(node.right, tainted, returners);}
  if (isBinaryShape(node)) {return binaryIsTainted(node, tainted, returners);}
  const inner = assertionExpr(node);
  if (inner !== undefined) {return exprIsTainted(inner, tainted, returners);}
  return false;
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
  return shapeIsTainted(node, tainted, returners);
}

interface Feed {
  tainted: Set<string>;
  returners: ReadonlySet<string>;
  nosqlSanitized: Set<string>;
  built: Set<string>;
  filterReturners: ReadonlySet<string>;
}

function feedElement(el: AstNode | null, feed: Feed): boolean {
  if (el === null) {return false;}
  if (el.type === 'SpreadElement') {return valueFeedsFilter(el.argument, feed);}
  return valueFeedsFilter(el, feed);
}

function feedProperty(prop: AstNode, feed: Feed): boolean {
  if (prop.type === 'SpreadElement') {return valueFeedsFilter(prop.argument, feed);}
  if (prop.type !== 'Property') {return false;}
  return valueFeedsFilter(prop.value, feed);
}

function assignFeeds(node: AstNode, feed: Feed): boolean {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return false;}
  if (node.callee.object.type !== 'Identifier' || node.callee.object.name !== 'Object') {return false;}
  if (propName(node.callee) !== 'assign') {return false;}
  return node.arguments.some((arg) => arg.type !== 'SpreadElement' && valueFeedsFilter(arg, feed));
}

function containerFeeds(node: AstNode, feed: Feed): boolean {
  if (node.type === 'ObjectExpression') {return node.properties.some((prop) => feedProperty(prop, feed));}
  if (node.type === 'ArrayExpression') {return node.elements.some((el) => feedElement(el, feed));}
  return assignFeeds(node, feed);
}

function namedFeeds(node: AstNode, feed: Feed): boolean | undefined {
  if (node.type !== 'Identifier') {return undefined;}
  if (feed.nosqlSanitized.has(node.name)) {return false;}
  return feed.built.has(node.name) || feed.tainted.has(node.name);
}

function wrappedFeeds(node: AstNode): boolean {
  return (
    node.type === 'ChainExpression' ||
    node.type === 'TSAsExpression' ||
    node.type === 'TSNonNullExpression' ||
    node.type === 'TSTypeAssertion' ||
    node.type === 'MemberExpression'
  );
}

/**
 * True when this value can put request data into a Mongo filter object.
 * A bare tainted name is not itself a built filter; an object, array, or
 * Object.assign that contains one is.
 */
function valueFeedsFilter(node: AstNode | undefined, feed: Feed): boolean {
  if (node === undefined) {return false;}
  if (isCoercionCall(node) || isSchemaValidatorCall(node) || isMongoSanitizeCall(node)) {return false;}
  const named = namedFeeds(node, feed);
  if (named !== undefined) {return named;}
  if (isRequestObjectNode(node)) {return true;}
  if (node.type === 'AwaitExpression') {return valueFeedsFilter(node.argument, feed);}
  if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && feed.filterReturners.has(node.callee.name)) {
    return true;
  }
  if (node.type === 'ObjectExpression' || node.type === 'ArrayExpression') {return containerFeeds(node, feed);}
  if (assignFeeds(node, feed)) {return true;}
  if (wrappedFeeds(node)) {return exprIsTainted(node, feed.tainted, feed.returners);}
  return false;
}

function initIsBuiltFilter(node: AstNode, feed: Feed): boolean {
  if (node.type === 'AwaitExpression') {return initIsBuiltFilter(node.argument, feed);}
  if (node.type === 'Identifier') {return feed.built.has(node.name) && !feed.nosqlSanitized.has(node.name);}
  if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && feed.filterReturners.has(node.callee.name)) {
    return true;
  }
  if (node.type === 'ObjectExpression' || node.type === 'ArrayExpression') {return valueFeedsFilter(node, feed);}
  return assignFeeds(node, feed);
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

interface Absorb {
  tainted: Set<string>;
  returners: ReadonlySet<string>;
  nosqlSanitized: Set<string>;
  sqlCleared: Set<string>;
  customPath: Set<string>;
  urlSanitized: Set<string>;
  xssSanitized: Set<string>;
  argvNames: Set<string>;
  note: (name: string) => void;
  changed: boolean;
}

function markSanitized(names: readonly string[], init: AstNode | undefined, state: Absorb): boolean {
  if (isSchemaValidatorCall(init) || isCoercionCall(init) || isMongoSanitizeCall(init)) {
    for (const name of names) {state.nosqlSanitized.add(name);}
  }
  return isSchemaValidatorCall(init);
}

function markTainted(names: readonly string[], init: AstNode | undefined, state: Absorb): void {
  applyCustomCall(init, names, state.tainted, state.sqlCleared, state.customPath);
  if (isUrlSanitizerCall(init)) {
    for (const name of names) {state.urlSanitized.add(name);}
  }
  if (isXssSanitizerCall(init)) {
    for (const name of names) {state.xssSanitized.add(name);}
  }
  if (!exprIsTainted(init, state.tainted, state.returners)) {return;}
  const argv = exprIsArgvDerived(init, state.argvNames);
  for (const name of names) {
    if (argv) {state.argvNames.add(name);}
    else {state.argvNames.delete(name); state.note(name);}
    if (!state.tainted.has(name)) {
      state.tainted.add(name);
      state.changed = true;
    }
  }
}

function markFlow2Field(node: AstNode, state: Absorb): void {
  if (!flow2Active || node.type !== 'AssignmentExpression' || node.left.type !== 'MemberExpression') {return;}
  if (node.left.computed === true || node.left.object.type !== 'Identifier') {return;}
  if (node.left.property.type !== 'Identifier') {return;}
  if (!exprIsTainted(node.right, state.tainted, state.returners)) {return;}
  const key = `${node.left.object.name}.${node.left.property.name}`;
  const line = startLine(node);
  if (line !== undefined) {
    const lines = fieldLines(state.tainted);
    const prev = lines.get(key);
    if (prev === undefined || line < prev) {
      lines.set(key, line);
      state.changed = true;
    }
  }
  const argv = exprIsArgvDerived(node.right, state.argvNames);
  if (!argv) {state.note(key);}
  if (state.tainted.has(key)) {return;}
  state.tainted.add(key);
  state.changed = true;
}

function absorbBindings(node: AstNode, state: Absorb): void {
  if (node.type === 'VariableDeclarator') {
    const init = node.init ?? undefined;
    const names = boundNames(node.id);
    if (markSanitized(names, init, state)) {return;}
    markTainted(names, init, state);
    return;
  }
  if (node.type !== 'AssignmentExpression') {return;}
  const names = boundNames(node.left);
  if (markSanitized(names, node.right, state)) {return;}
  markTainted(names, node.right, state);
  markFlow2Field(node, state);
}

function resolvedNames(scope: AstNode): Set<string> {
  const resolved = new Set<string>();
  walkScope(scope, (node) => {
    if (node.type === 'VariableDeclarator' && node.init !== null && isPathResolveCall(node.init)) {
      for (const name of boundNames(node.id)) {resolved.add(name);}
    }
    if (node.type === 'AssignmentExpression' && isPathResolveCall(node.right)) {
      for (const name of boundNames(node.left)) {resolved.add(name);}
    }
  });
  return resolved;
}

function pathSanitizedNames(scope: AstNode, customPath: ReadonlySet<string>): Set<string> {
  const resolved = resolvedNames(scope);
  const pathSanitized = new Set<string>(customPath);
  walkScope(scope, (node) => {
    if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return;}
    if (propName(node.callee) !== 'startsWith') {return;}
    if (node.callee.object.type === 'Identifier' && resolved.has(node.callee.object.name)) {
      pathSanitized.add(node.callee.object.name);
    }
  });
  return pathSanitized;
}

function scopeHasPassword(scope: AstNode): boolean {
  if (scope.type === 'FunctionDeclaration' && scope.id !== null && /password|passwd|pwd/i.test(scope.id.name)) {
    return true;
  }
  let has = false;
  walkScope(scope, (node) => {
    if (node.type === 'Identifier' && /password|passwd|pwd/i.test(node.name)) {has = true;}
  });
  return has;
}

function decoratorNames(param: AstNode): readonly string[] {
  const nest = nestInputDecorator(param);
  if (nest !== 'Body' && nest !== 'Query' && nest !== 'Param') {return [];}
  if (nestDecoratorArgCount(param, nest) !== 0) {return [];}
  return boundNames(param);
}

function addRequest(
  names: Set<string>,
  target: AstNode,
  init: AstNode | null | undefined,
  from: (node: AstNode) => boolean,
): void {
  if (init === null || init === undefined || !from(init)) {return;}
  for (const name of boundNames(target)) {names.add(name);}
}

function collectRequestObjects(scope: AstNode): Set<string> {
  const names = new Set<string>();
  if (frameworksEnabled() && isFunctionNode(scope)) {
    for (const param of scope.params) {
      for (const name of decoratorNames(param)) {names.add(name);}
    }
  }
  walkScope(scope, (node) => {
    if (node.type === 'VariableDeclarator') {
      addRequest(names, node.id, node.init, isRequestObjectNode);
      addRequest(names, node.id, node.init, isFrameworkRequestObject);
    }
    if (node.type === 'AssignmentExpression') {
      addRequest(names, node.left, node.right, isRequestObjectNode);
      addRequest(names, node.left, node.right, isFrameworkRequestObject);
    }
  });
  return names;
}

function builtNames(node: AstNode, feed: Feed): string[] {
  if (node.type === 'VariableDeclarator' && node.init !== null && initIsBuiltFilter(node.init, feed)) {
    return boundNames(node.id);
  }
  if (node.type !== 'AssignmentExpression') {return [];}
  if (node.left.type === 'Identifier' && initIsBuiltFilter(node.right, feed)) {return [node.left.name];}
  if (
    node.left.type === 'MemberExpression' &&
    node.left.object.type === 'Identifier' &&
    valueFeedsFilter(node.right, feed)
  ) {
    return [node.left.object.name];
  }
  return [];
}

function collectBuiltFilters(
  scope: AstNode,
  state: Absorb,
  filterReturners: ReadonlySet<string>,
  initialBuilt: ReadonlySet<string>,
): Set<string> {
  const built = new Set<string>(initialBuilt);
  const feed: Feed = {
    tainted: state.tainted,
    returners: state.returners,
    nosqlSanitized: state.nosqlSanitized,
    built,
    filterReturners,
  };
  let grew = true;
  while (grew) {
    grew = false;
    walkScope(scope, (node) => {
      for (const name of builtNames(node, feed)) {
        if (state.nosqlSanitized.has(name) || built.has(name)) {continue;}
        built.add(name);
        grew = true;
      }
    });
  }
  return built;
}

function analyzeScope(
  scope: AstNode,
  seed: Iterable<string> = [],
  returners: ReadonlySet<string> = NO_RETURNERS,
  filterReturners: ReadonlySet<string> = NO_RETURNERS,
  initialBuilt: ReadonlySet<string> = NO_RETURNERS,
): ScopeFacts {
  const tainted = new Set<string>(seed);
  const seedNames = new Set<string>(seed);
  const born = new Set<string>();
  const note = (name: string): void => {
    if (!seedNames.has(name)) {born.add(name);}
  };
  seedDestructuredRequestParams(scope, tainted);
  seedFrameworkParams(scope, tainted);
  seedMcpToolParams(scope, tainted);
  const state: Absorb = {
    tainted,
    returners,
    nosqlSanitized: new Set<string>(),
    sqlCleared: new Set<string>(),
    customPath: new Set<string>(),
    urlSanitized: new Set<string>(),
    xssSanitized: new Set<string>(),
    argvNames: new Set<string>(),
    note,
    changed: false,
  };
  let pending = true;
  while (pending) {
    state.changed = false;
    walkScope(scope, (node) => {absorbBindings(node, state);});
    pending = state.changed;
  }
  flow2LocalTaint.set(scope, born);
  return {
    tainted,
    pathSanitized: pathSanitizedNames(scope, state.customPath),
    sqlCleared: state.sqlCleared,
    urlSanitized: state.urlSanitized,
    xssSanitized: state.xssSanitized,
    nosqlSanitized: state.nosqlSanitized,
    hasPasswordName: scopeHasPassword(scope),
    requestObjects: collectRequestObjects(scope),
    builtFilters: collectBuiltFilters(scope, state, filterReturners, initialBuilt),
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
      initIsBuiltFilter(node.argument, {
        tainted: facts.tainted,
        returners: facts.returners,
        nosqlSanitized: facts.nosqlSanitized,
        built: facts.builtFilters,
        filterReturners: facts.filterReturners,
      })
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

function noteThisAssign(node: AstNode, tainted: Set<string>, returners: ReadonlySet<string>): boolean {
  if (node.type !== 'AssignmentExpression' || node.left.type !== 'MemberExpression') {return false;}
  if (node.left.object.type !== 'ThisExpression' || !exprIsTainted(node.right, tainted, returners)) {return false;}
  const cls = enclosingClass(node);
  const field = propName(node.left);
  if (cls === undefined || field === undefined) {return false;}
  const fields = taintedThisFields.get(cls) ?? new Set<string>();
  if (fields.has(field)) {return false;}
  fields.add(field);
  taintedThisFields.set(cls, fields);
  return true;
}

function noteCallbackSeed(
  node: AstNode,
  mark: (fn: AstNode, name: string | undefined) => void,
  tainted: Set<string>,
  returners: ReadonlySet<string>,
): void {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return;}
  const method = propName(node.callee);
  if (method === undefined || !CALLBACK_METHODS.has(method)) {return;}
  if (!exprIsTainted(node.callee.object, tainted, returners)) {return;}
  const callback = node.arguments[0];
  if (callback !== undefined && isFunctionNode(callback)) {
    mark(callback, boundNames(callback.params[0])[0]);
  }
}

function noteApplySeed(
  node: AstNode,
  mark: (fn: AstNode, name: string | undefined) => void,
  tainted: Set<string>,
  returners: ReadonlySet<string>,
  nameToFn: Map<string, AstNode>,
): void {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return;}
  const method = propName(node.callee);
  if (method !== 'call' && method !== 'apply') {return;}
  if (node.callee.object.type !== 'Identifier') {return;}
  const target = nameToFn.get(node.callee.object.name);
  if (target === undefined || !isFunctionNode(target)) {return;}
  const arg = node.arguments[1];
  if (arg !== undefined && arg.type !== 'SpreadElement' && exprIsTainted(arg, tainted, returners)) {
    mark(target, boundNames(target.params[0])[0]);
  }
}

function noteMethodSeed(
  node: AstNode,
  mark: (fn: AstNode, name: string | undefined) => void,
  tainted: Set<string>,
  returners: ReadonlySet<string>,
  nameToFn: Map<string, AstNode>,
): void {
  noteCallbackSeed(node, mark, tainted, returners);
  noteApplySeed(node, mark, tainted, returners, nameToFn);
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
      if (noteThisAssign(node, f.tainted, returners)) {changed = true;}
      noteMethodSeed(node, mark, f.tainted, returners, nameToFn);
    });
  }
  return changed;
}

function seedFromCall(
  node: AstNode,
  tainted: Set<string>,
  returners: ReadonlySet<string>,
  nameToFn: Map<string, AstNode>,
  seeds: Map<AstNode, Set<string>>,
): boolean {
  if (node.type !== 'CallExpression' || node.callee.type !== 'Identifier') {return false;}
  const callee = nameToFn.get(node.callee.name);
  if (callee === undefined || !isFunctionNode(callee)) {return false;}
  let changed = false;
  node.arguments.forEach((arg, i) => {
    if (arg.type === 'SpreadElement' || !exprIsTainted(arg, tainted, returners)) {return;}
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
  return changed;
}

function noteReturners(
  functions: AstNode[],
  facts: WeakMap<AstNode, ScopeFacts>,
  returners: Set<string>,
  filterReturners: Set<string>,
): boolean {
  let changed = false;
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
  return changed;
}

interface HopState {
  functions: AstNode[];
  facts: WeakMap<AstNode, ScopeFacts>;
  seeds: Map<AstNode, Set<string>>;
  returners: Set<string>;
  filterReturners: Set<string>;
  nameToFn: Map<string, AstNode>;
}

function refreshHop(ast: AstNode, hop: HopState): boolean {
  let changed = false;
  hop.facts.set(ast, analyzeScope(ast, [], hop.returners, hop.filterReturners));
  for (const fn of hop.functions) {
    hop.facts.set(
      fn,
      analyzeScope(fn, hop.seeds.get(fn) ?? [], hop.returners, hop.filterReturners, inheritedBuiltFilters(fn, hop.facts)),
    );
  }
  if (noteReturners(hop.functions, hop.facts, hop.returners, hop.filterReturners)) {changed = true;}
  for (const fn of hop.functions) {
    const f = hop.facts.get(fn);
    if (f === undefined) {continue;}
    walkScope(fn, (node) => {
      if (seedFromCall(node, f.tainted, hop.returners, hop.nameToFn, hop.seeds)) {changed = true;}
    });
  }
  if (taintV2Enabled() && seedTaintV2(hop.functions, hop.facts, hop.seeds, hop.returners, hop.nameToFn)) {changed = true;}
  if (flow2Seed !== undefined && flow2Seed(hop.functions, hop.seeds)) {changed = true;}
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
    if (!refreshHop(ast, { functions, facts, seeds, returners, filterReturners, nameToFn })) {break;}
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
