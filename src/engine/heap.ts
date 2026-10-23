import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

/** Phase 252. Field-sensitive heap. Collapse keeps taint (sound). */
export const HEAP_FLAG = 'FULLSHIELD_EXPERIMENTAL_HEAP';

export function heapEnabled(): boolean {
  return process.env[HEAP_FLAG] === '1';
}

export interface HeapFinding {
  path: string;
  line: number;
}

const SOURCE_PROPS = new Set(['query', 'body', 'params', 'headers', 'cookies']);

function isRequest(node: TSESTree.Node): boolean {
  let current: TSESTree.Node | undefined = node;
  while (current?.type === 'MemberExpression') {
    if (current.property.type === 'Identifier' && SOURCE_PROPS.has(current.property.name)) {
      let root: TSESTree.Node = current.object;
      while (root.type === 'MemberExpression') {root = root.object;}
      if (root.type === 'Identifier' && root.name === 'req') {return true;}
    }
    current = current.object;
  }
  return false;
}

function exprTainted(node: TSESTree.Node, taintedNames: ReadonlySet<string>): boolean {
  if (node.type === 'Identifier') {return taintedNames.has(node.name);}
  if (node.type === 'Literal' || node.type === 'TemplateLiteral') {return false;}
  if (isRequest(node)) {return true;}
  if (node.type === 'MemberExpression') {return exprTainted(node.object, taintedNames);}
  if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression') {
    return exprTainted(node.left, taintedNames) || exprTainted(node.right, taintedNames);
  }
  if (node.type === 'CallExpression') {
    return node.arguments.some((arg) => arg.type !== 'SpreadElement' && exprTainted(arg, taintedNames));
  }
  return false;
}

/** Paths longer than `limit` collapse onto the prefix and keep taint. */
export function collapsePath(parts: readonly string[], limit = 3): string {
  if (parts.length <= limit) {return parts.join('.');}
  return parts.slice(0, limit).join('.');
}

interface ObjFields {
  fields: Map<string, boolean>;
}

function memberPath(node: TSESTree.MemberExpression): string[] | undefined {
  const parts: string[] = [];
  let current: TSESTree.Node = node;
  while (current.type === 'MemberExpression') {
    if (current.property.type !== 'Identifier' || current.computed === true) {return undefined;}
    parts.unshift(current.property.name);
    current = current.object;
  }
  if (current.type !== 'Identifier') {return undefined;}
  parts.unshift(current.name);
  return parts;
}

interface HeapState {
  objects: Map<string, ObjFields>;
  taintedNames: Set<string>;
  findings: HeapFinding[];
  depthLimit: number;
}

function isAstNode(value: unknown): value is TSESTree.Node {
  return value !== null && typeof value === 'object' && 'type' in value;
}

function walkAst(node: TSESTree.Node, visit: (node: TSESTree.Node) => void): void {
  for (const key of Object.keys(node)) {
    if (key === 'parent') {continue;}
    const value = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isAstNode(item)) {visit(item);}
      }
    } else if (isAstNode(value)) {
      visit(value);
    }
  }
}

function writeField(fields: Map<string, boolean>, parts: string[], tainted: boolean, depthLimit: number): void {
  const key = collapsePath(parts, depthLimit);
  fields.set(key, (fields.get(key) ?? false) || tainted);
}

function storeFields(
  fields: Map<string, boolean>,
  prefix: string[],
  expr: TSESTree.Node,
  taintedNames: ReadonlySet<string>,
  depthLimit: number,
): void {
  if (expr.type === 'ObjectExpression') {
    for (const prop of expr.properties) {
      if (prop.type !== 'Property' || prop.computed === true || prop.key.type !== 'Identifier') {continue;}
      storeFields(fields, [...prefix, prop.key.name], prop.value, taintedNames, depthLimit);
    }
    return;
  }
  writeField(fields, prefix, exprTainted(expr, taintedNames), depthLimit);
}

function storeObject(state: HeapState, name: string, expr: TSESTree.ObjectExpression): void {
  const fields: ObjFields = { fields: new Map() };
  storeFields(fields.fields, [], expr, state.taintedNames, state.depthLimit);
  state.objects.set(name, fields);
}

function noteBinding(node: TSESTree.Node, state: HeapState): void {
  if (node.type !== 'VariableDeclarator' || node.id.type !== 'Identifier' || node.init === null) {return;}
  if (node.init.type === 'ObjectExpression') {
    storeObject(state, node.id.name, node.init);
    return;
  }
  if (exprTainted(node.init, state.taintedNames)) {state.taintedNames.add(node.id.name);}
}

function noteQuery(node: TSESTree.Node, state: HeapState): void {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return;}
  const property = node.callee.property;
  if (property.type !== 'Identifier' || (property.name !== 'query' && property.name !== 'exec')) {return;}
  for (const arg of node.arguments) {noteQueryArg(arg, state);}
}

function noteQueryArg(arg: TSESTree.CallExpressionArgument, state: HeapState): void {
  if (arg.type !== 'MemberExpression' && arg.type !== 'BinaryExpression') {return;}
  const reads = arg.type === 'MemberExpression' ? [arg] : memberReads(arg);
  for (const read of reads) {noteFieldRead(read, state);}
}

function noteFieldRead(read: TSESTree.MemberExpression, state: HeapState): void {
  const parts = memberPath(read);
  if (parts === undefined || parts.length < 2) {return;}
  const root = parts[0];
  if (root === undefined) {return;}
  const obj = state.objects.get(root);
  if (obj === undefined) {return;}
  const collapsed = collapsePath(parts.slice(1), state.depthLimit);
  if (obj.fields.get(collapsed) !== true) {return;}
  state.findings.push({ path: `${root}.${collapsed}`, line: read.loc?.start.line ?? 1 });
}

function visitHeap(node: TSESTree.Node, state: HeapState): void {
  noteBinding(node, state);
  noteQuery(node, state);
  walkAst(node, (child) => { visitHeap(child, state); });
}

export function heapFindings(source: string, depthLimit = 3): HeapFinding[] {
  if (!heapEnabled()) {return [];}
  const program = parse(source, {
    loc: true,
    range: true,
    jsx: false,
    comment: false,
    errorOnUnknownASTType: false,
    errorOnTypeScriptSyntacticAndSemanticIssues: false,
  });
  const state: HeapState = {
    objects: new Map(),
    taintedNames: new Set(),
    findings: [],
    depthLimit,
  };
  visitHeap(program, state);
  return state.findings;
}

function memberReads(node: TSESTree.BinaryExpression): TSESTree.MemberExpression[] {
  const out: TSESTree.MemberExpression[] = [];
  const walk = (current: TSESTree.Node): void => {
    if (current.type === 'MemberExpression') {out.push(current); return;}
    if (current.type === 'BinaryExpression') {
      walk(current.left);
      walk(current.right);
    }
  };
  walk(node);
  return out;
}

/** Depth-4 store collapses onto the depth-3 prefix and keeps the taint bit. */
export function collapseKeepsTaint(parts: readonly string[], tainted: boolean, limit = 3): boolean {
  if (!tainted) {return false;}
  return collapsePath(parts, limit).length > 0;
}
