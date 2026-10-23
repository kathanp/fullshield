import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { parse, type TSESTree } from '@typescript-eslint/typescript-estree';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SOUNDNESS';

/** Closed set from the phase 271 analysis contract. */
export const UNSOUND_KINDS = [
  'dynamic-property',
  'eval',
  'unresolved-import',
  'depth-cap',
  'fixpoint-cap',
  'unknown-callee',
  'proxy',
] as const;

export type UnsoundKind = (typeof UNSOUND_KINDS)[number];

export type SoundMode = 'precise' | 'sound';

export interface UnsoundEvent {
  kind: UnsoundKind;
  file: string;
  line: number;
  reason: string;
}

export interface SoundnessFinding {
  file: string;
  line: number;
  sinkClass: string;
  mode: 'sound';
}

export interface SoundnessAnalysis {
  events: UnsoundEvent[];
  findings: SoundnessFinding[];
}

export interface SoundnessReport {
  countsByKind: Record<UnsoundKind, number>;
  countsByFile: Record<string, number>;
  topFiles: { file: string; count: number }[];
}

export interface SoundnessOptions {
  file?: string;
  mode?: SoundMode;
  depthCap?: number;
  fixpointCap?: number;
  /** Relative specifiers listed here are resolved. Bare specifiers are external. */
  resolvedSpecifiers?: readonly string[];
}

interface Taint {
  direct: boolean;
  viaUnknown: boolean;
}

interface Edge {
  to: string;
  line: number;
}

const REQUEST_PROPS: ReadonlySet<string> = new Set(['query', 'body', 'params', 'headers', 'files', 'file']);

const BUILTINS: ReadonlySet<string> = new Set([
  'require', 'Number', 'String', 'Boolean', 'BigInt', 'Symbol', 'parseInt', 'parseFloat',
  'isNaN', 'isFinite', 'Object', 'Array', 'JSON', 'Math', 'Date', 'RegExp', 'Promise',
  'Error', 'TypeError', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Reflect', 'Proxy',
  'setTimeout', 'setInterval', 'setImmediate', 'queueMicrotask', 'clearTimeout', 'clearInterval',
  'decodeURIComponent', 'encodeURIComponent', 'decodeURI', 'encodeURI',
  'atob', 'btoa', 'structuredClone',
]);

const SINK_METHODS: ReadonlyMap<string, string> = new Map([
  ['query', 'sqli'],
  ['execute', 'sqli'],
  ['exec', 'cmdi'],
  ['execSync', 'cmdi'],
  ['spawn', 'cmdi'],
  ['send', 'xss'],
  ['write', 'xss'],
]);

const PARSE_OPTIONS = {
  loc: true,
  range: true,
  comment: false,
  jsx: true,
  errorOnUnknownASTType: false,
  errorOnTypeScriptSyntacticAndSemanticIssues: false,
} as const;

const TOP_FILES = 50;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function parseProgram(code: string): TSESTree.Program | null {
  try {
    return parse(code, { ...PARSE_OPTIONS, sourceType: 'module' });
  } catch {
    try {
      return parse(code, { ...PARSE_OPTIONS, sourceType: 'script' });
    } catch {
      return null;
    }
  }
}

export function lineOf(node: TSESTree.Node): number {
  return node.loc?.start.line ?? 1;
}

export function isAstNode(value: unknown): value is TSESTree.Node {
  if (typeof value !== 'object' || value === null) {return false;}
  if (!('type' in value)) {return false;}
  return typeof value.type === 'string';
}

export function walkAst(node: TSESTree.Node, visit: (current: TSESTree.Node) => void): void {
  visit(node);
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'range' || key === 'parent' || key === 'start' || key === 'end') {continue;}
    const child: unknown = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (isAstNode(item)) {walkAst(item, visit);}
      }
    } else if (isAstNode(child)) {
      walkAst(child, visit);
    }
  }
}

export function propName(node: TSESTree.MemberExpression): string | null {
  if (!node.computed && node.property.type === 'Identifier') {return node.property.name;}
  if (node.computed && node.property.type === 'Literal' && typeof node.property.value === 'string') {
    return node.property.value;
  }
  return null;
}

export function stripNode(node: TSESTree.Node): TSESTree.Node {
  if (node.type === 'ChainExpression') {return stripNode(node.expression);}
  if (
    node.type === 'TSAsExpression'
    || node.type === 'TSTypeAssertion'
    || node.type === 'TSNonNullExpression'
    || node.type === 'TSSatisfiesExpression'
  ) {
    return stripNode(node.expression);
  }
  return node;
}

/** `req.query` / `req.body` / `req.params` / `req.headers` / `req.files` and their fields. */
export function isRequestSource(node: TSESTree.Node): boolean {
  const current = stripNode(node);
  if (current.type !== 'MemberExpression') {return false;}
  if (isRequestRoot(current)) {return true;}
  return isRequestSource(current.object);
}

export function analyzeSoundness(source: string, options?: SoundnessOptions): SoundnessAnalysis {
  if (!enabled()) {return { events: [], findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { events: [], findings: [] };}
  const file = options?.file ?? 'inline.js';
  const mode: SoundMode = options?.mode ?? 'precise';
  const depthCap = options?.depthCap ?? 64;
  const events: UnsoundEvent[] = [];
  const locals = collectLocals(program);
  collectStructuralEvents(program, file, locals, options?.resolvedSpecifiers ?? [], events);
  collectDepthAndFixpoint(program, file, depthCap, events);
  const findings = mode === 'sound' ? collectSoundFindings(program, file, locals) : [];
  return { events, findings };
}

export function buildSoundnessReport(events: readonly UnsoundEvent[]): SoundnessReport {
  const countsByKind = emptyKindCounts();
  const byFile = new Map<string, number>();
  for (const event of events) {
    countsByKind[event.kind] += 1;
    byFile.set(event.file, (byFile.get(event.file) ?? 0) + 1);
  }
  const topFiles = [...byFile.entries()]
    .sort((left, right) => {
      if (right[1] !== left[1]) {return right[1] - left[1];}
      if (left[0] < right[0]) {return -1;}
      if (left[0] > right[0]) {return 1;}
      return 0;
    })
    .slice(0, TOP_FILES)
    .map(([file, count]) => ({ file, count }));
  const countsByFile: Record<string, number> = {};
  for (const key of [...byFile.keys()].sort()) {
    countsByFile[key] = byFile.get(key) ?? 0;
  }
  return { countsByKind, countsByFile, topFiles };
}

/** Writes `.fullshield/soundness.json`. Paths and counts only; source text is never copied. */
export function writeSoundnessReport(directory: string, events: readonly UnsoundEvent[]): SoundnessReport {
  if (!enabled()) {return buildSoundnessReport([]);}
  const report = buildSoundnessReport(events);
  const dir = join(directory, '.fullshield');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'soundness.json'), `${JSON.stringify(report)}\n`);
  return report;
}

function emptyKindCounts(): Record<UnsoundKind, number> {
  return {
    'dynamic-property': 0,
    eval: 0,
    'unresolved-import': 0,
    'depth-cap': 0,
    'fixpoint-cap': 0,
    'unknown-callee': 0,
    proxy: 0,
  };
}

function isRequestRoot(node: TSESTree.MemberExpression): boolean {
  if (node.object.type !== 'Identifier' || node.object.name !== 'req') {return false;}
  const name = propName(node);
  return name !== null && REQUEST_PROPS.has(name);
}

function collectLocals(program: TSESTree.Program): Set<string> {
  const names = new Set<string>();
  walkAst(program, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id !== null) {names.add(node.id.name);}
    if (node.type === 'ClassDeclaration' && node.id !== null) {names.add(node.id.name);}
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init !== null && isFunctionLike(node.init)) {
      names.add(node.id.name);
    }
    if (node.type === 'ImportDeclaration') {
      for (const spec of node.specifiers) {names.add(spec.local.name);}
    }
  });
  return names;
}

function isFunctionLike(node: TSESTree.Node): boolean {
  const current = stripNode(node);
  return current.type === 'FunctionExpression' || current.type === 'ArrowFunctionExpression' || current.type === 'FunctionDeclaration';
}

function collectStructuralEvents(
  program: TSESTree.Program,
  file: string,
  locals: ReadonlySet<string>,
  resolved: readonly string[],
  events: UnsoundEvent[],
): void {
  const resolvedSet = new Set(resolved);
  walkAst(program, (node) => {
    noteStructuralNode(node, file, locals, resolvedSet, events);
  });
}

function noteStructuralNode(
  node: TSESTree.Node,
  file: string,
  locals: ReadonlySet<string>,
  resolved: ReadonlySet<string>,
  events: UnsoundEvent[],
): void {
  noteDynamicOrProxy(node, file, events);
  if (node.type === 'CallExpression' || node.type === 'NewExpression') {
    noteCallEvent(node, file, locals, events);
  }
  noteImportNode(node, file, resolved, events);
}

function noteDynamicOrProxy(node: TSESTree.Node, file: string, events: UnsoundEvent[]): void {
  if (node.type === 'MemberExpression' && node.computed && propName(node) === null) {
    pushEvent(events, 'dynamic-property', file, lineOf(node), 'dynamic property name');
  }
  noteProxyOrFunction(node, file, events);
}

function noteProxyOrFunction(node: TSESTree.Node, file: string, events: UnsoundEvent[]): void {
  if (node.type !== 'NewExpression' || node.callee.type !== 'Identifier') {return;}
  if (node.callee.name === 'Proxy') {pushEvent(events, 'proxy', file, lineOf(node), 'Proxy');}
  if (node.callee.name === 'Function') {pushEvent(events, 'eval', file, lineOf(node), 'eval or Function');}
}

function noteImportNode(
  node: TSESTree.Node,
  file: string,
  resolved: ReadonlySet<string>,
  events: UnsoundEvent[],
): void {
  if (node.type === 'ImportExpression' || node.type === 'ImportDeclaration') {
    noteSpecifier(node.source, file, resolved, events, lineOf(node));
    return;
  }
  if (isExportFrom(node) && node.source !== null) {
    noteSpecifier(node.source, file, resolved, events, lineOf(node));
  }
}

function isExportFrom(node: TSESTree.Node): node is TSESTree.ExportAllDeclaration | TSESTree.ExportNamedDeclaration {
  return node.type === 'ExportAllDeclaration' || node.type === 'ExportNamedDeclaration';
}

function noteCallEvent(
  node: TSESTree.CallExpression | TSESTree.NewExpression,
  file: string,
  locals: ReadonlySet<string>,
  events: UnsoundEvent[],
): void {
  if (node.type === 'NewExpression') {return;}
  const callee = stripNode(node.callee);
  if (callee.type === 'Identifier' && (callee.name === 'eval' || callee.name === 'Function')) {
    pushEvent(events, 'eval', file, lineOf(node), 'eval or Function');
    return;
  }
  if (callee.type === 'Identifier' && callee.name === 'require') {
    const arg = node.arguments[0];
    if (arg !== undefined && arg.type !== 'SpreadElement') {noteSpecifier(arg, file, new Set(), events, lineOf(node));}
    return;
  }
  if (callee.type === 'Identifier' && !locals.has(callee.name) && !BUILTINS.has(callee.name)) {
    pushEvent(events, 'unknown-callee', file, lineOf(node), 'unknown callee');
  }
}

function noteSpecifier(
  node: TSESTree.Node,
  file: string,
  resolved: ReadonlySet<string>,
  events: UnsoundEvent[],
  line: number,
): void {
  if (node.type !== 'Literal' || typeof node.value !== 'string') {return;}
  const spec = node.value;
  if (!spec.startsWith('.') && !spec.startsWith('/')) {return;}
  if (resolved.has(spec)) {return;}
  pushEvent(events, 'unresolved-import', file, line, 'unresolved import');
}

function pushEvent(events: UnsoundEvent[], kind: UnsoundKind, file: string, line: number, reason: string): void {
  if (events.some((event) => event.kind === kind && event.file === file && event.line === line && event.reason === reason)) {
    return;
  }
  events.push({ kind, file, line, reason });
}

function collectDepthAndFixpoint(program: TSESTree.Program, file: string, depthCap: number, events: UnsoundEvent[]): void {
  const graph = new Map<string, Edge[]>();
  const locals = collectLocals(program);
  walkAst(program, (node) => {
    if (!isFunctionWithBody(node)) {return;}
    const name = functionName(node);
    if (name === null) {return;}
    const edges = graph.get(name) ?? [];
    graph.set(name, edges);
    walkAst(node.body ?? node, (inner) => {
      if (inner.type !== 'CallExpression') {return;}
      const callee = stripNode(inner.callee);
      if (callee.type === 'Identifier' && locals.has(callee.name)) {
        edges.push({ to: callee.name, line: lineOf(inner) });
      }
    });
  });
  const topEdges: Edge[] = [];
  for (const stmt of program.body) {
    if (stmt.type !== 'ExpressionStatement' && stmt.type !== 'VariableDeclaration') {continue;}
    walkAst(stmt, (inner) => {
      if (inner.type !== 'CallExpression') {return;}
      const callee = stripNode(inner.callee);
      if (callee.type === 'Identifier' && locals.has(callee.name)) {
        topEdges.push({ to: callee.name, line: lineOf(inner) });
      }
    });
  }
  graph.set('<top>', topEdges);

  let depthLine = 1;
  let longest = 0;
  for (const name of graph.keys()) {
    const hops = longestPath(name, graph, new Set());
    if (hops > longest) {
      longest = hops;
      depthLine = (graph.get(name) ?? [])[0]?.line ?? 1;
    }
  }
  if (longest > depthCap) {
    pushEvent(events, 'depth-cap', file, depthLine, 'depth cap');
  }

  const color = new Map<string, number>();
  const visit = (name: string): void => {
    color.set(name, 1);
    for (const edge of graph.get(name) ?? []) {
      const state = color.get(edge.to) ?? 0;
      if (state === 1) {
        pushEvent(events, 'fixpoint-cap', file, edge.line, 'fixpoint cap');
      } else if (state === 0) {
        visit(edge.to);
      }
    }
    color.set(name, 2);
  };
  for (const name of graph.keys()) {
    if ((color.get(name) ?? 0) === 0) {visit(name);}
  }
}

function longestPath(name: string, graph: ReadonlyMap<string, readonly Edge[]>, path: Set<string>): number {
  if (path.has(name)) {return 0;}
  path.add(name);
  let best = 0;
  for (const edge of graph.get(name) ?? []) {
    if (path.has(edge.to)) {continue;}
    const hops = 1 + longestPath(edge.to, graph, path);
    if (hops > best) {best = hops;}
  }
  path.delete(name);
  return best;
}

function isFunctionWithBody(node: TSESTree.Node): node is TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression {
  return node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression';
}

function functionName(node: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression): string | null {
  if (node.type !== 'ArrowFunctionExpression' && node.id !== null) {return node.id.name;}
  return null;
}

function collectSoundFindings(program: TSESTree.Program, file: string, locals: ReadonlySet<string>): SoundnessFinding[] {
  const findings: SoundnessFinding[] = [];
  const env = new Map<string, Taint>();
  const visitFn = (body: TSESTree.Statement[] | TSESTree.Expression): void => {
    const saved = new Map(env);
    env.clear();
    if (Array.isArray(body)) {execBlock(body, env, locals, findings, file);}
    else {noteExpression(body, env, locals, findings, file);}
    env.clear();
    for (const [key, value] of saved) {env.set(key, value);}
  };
  walkAst(program, (node) => {
    if (node.type === 'FunctionDeclaration' && node.body.type === 'BlockStatement') {
      visitFn(node.body.body);
    }
  });
  execBlock(program.body, env, locals, findings, file);
  return findings;
}

function execBlock(
  body: readonly TSESTree.Statement[],
  env: Map<string, Taint>,
  locals: ReadonlySet<string>,
  findings: SoundnessFinding[],
  file: string,
): void {
  for (const stmt of body) {execStmt(stmt, env, locals, findings, file);}
}

function execStmt(
  stmt: TSESTree.Statement,
  env: Map<string, Taint>,
  locals: ReadonlySet<string>,
  findings: SoundnessFinding[],
  file: string,
): void {
  if (stmt.type === 'BlockStatement') {
    execBlock(stmt.body, env, locals, findings, file);
    return;
  }
  if (isSkippedStmt(stmt)) {return;}
  if (stmt.type === 'VariableDeclaration') {
    execVarDecl(stmt, env, locals, findings, file);
    return;
  }
  if (stmt.type === 'ExpressionStatement') {
    execExprStmt(stmt, env, locals, findings, file);
    return;
  }
  if (stmt.type === 'ReturnStatement' && stmt.argument !== null) {
    noteExpression(stmt.argument, env, locals, findings, file);
    return;
  }
  if (stmt.type === 'IfStatement') {execIf(stmt, env, locals, findings, file);}
}

function isSkippedStmt(stmt: TSESTree.Statement): boolean {
  return stmt.type === 'FunctionDeclaration' || stmt.type === 'ClassDeclaration' || stmt.type === 'ImportDeclaration';
}

function execVarDecl(
  stmt: TSESTree.VariableDeclaration,
  env: Map<string, Taint>,
  locals: ReadonlySet<string>,
  findings: SoundnessFinding[],
  file: string,
): void {
  for (const decl of stmt.declarations) {
    if (decl.id.type === 'Identifier' && decl.init !== null) {
      env.set(decl.id.name, taintOf(decl.init, env, locals));
    }
  }
  noteExpression(stmt, env, locals, findings, file);
}

function execExprStmt(
  stmt: TSESTree.ExpressionStatement,
  env: Map<string, Taint>,
  locals: ReadonlySet<string>,
  findings: SoundnessFinding[],
  file: string,
): void {
  const expr = stripNode(stmt.expression);
  if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {
    env.set(expr.left.name, taintOf(expr.right, env, locals));
  }
  noteExpression(expr, env, locals, findings, file);
}

function execIf(
  stmt: TSESTree.IfStatement,
  env: Map<string, Taint>,
  locals: ReadonlySet<string>,
  findings: SoundnessFinding[],
  file: string,
): void {
  const saved = new Map(env);
  execStmt(stmt.consequent, env, locals, findings, file);
  const left = new Map(env);
  env.clear();
  for (const [key, value] of saved) {env.set(key, value);}
  if (stmt.alternate !== null) {execStmt(stmt.alternate, env, locals, findings, file);}
  joinEnv(env, left, saved);
}

function joinEnv(env: Map<string, Taint>, left: ReadonlyMap<string, Taint>, saved: ReadonlyMap<string, Taint>): void {
  const keys = new Set<string>([...env.keys(), ...left.keys(), ...saved.keys()]);
  const next = new Map<string, Taint>();
  for (const key of keys) {
    const none: Taint = { direct: false, viaUnknown: false };
    const l = left.get(key) ?? saved.get(key) ?? none;
    const r = env.get(key) ?? saved.get(key) ?? none;
    if (!l.direct && !l.viaUnknown && !r.direct && !r.viaUnknown) {continue;}
    next.set(key, { direct: l.direct || r.direct, viaUnknown: l.viaUnknown || r.viaUnknown });
  }
  env.clear();
  for (const [key, value] of next) {env.set(key, value);}
}

function noteExpression(
  node: TSESTree.Node,
  env: Map<string, Taint>,
  locals: ReadonlySet<string>,
  findings: SoundnessFinding[],
  file: string,
): void {
  walkAst(node, (current) => {
    if (current.type !== 'CallExpression') {return;}
    const callee = stripNode(current.callee);
    if (callee.type !== 'MemberExpression') {return;}
    const name = propName(callee);
    if (name === null) {return;}
    const sinkClass = SINK_METHODS.get(name);
    if (sinkClass === undefined) {return;}
    for (const arg of current.arguments) {
      if (arg.type === 'SpreadElement') {continue;}
      const taint = taintOf(arg, env, locals);
      if (taint.viaUnknown) {
        findings.push({ file, line: lineOf(current), sinkClass, mode: 'sound' });
        return;
      }
    }
  });
}

function taintOf(node: TSESTree.Node, env: ReadonlyMap<string, Taint>, locals: ReadonlySet<string>): Taint {
  const current = stripNode(node);
  if (isRequestSource(current)) {return { direct: true, viaUnknown: false };}
  if (current.type === 'Identifier') {return readTaint(env, current.name);}
  if (current.type === 'TemplateLiteral') {return orAll(current.expressions, env, locals);}
  if (current.type === 'BinaryExpression' && current.operator === '+') {
    return orTaint(taintOf(current.left, env, locals), taintOf(current.right, env, locals));
  }
  if (current.type === 'MemberExpression') {return taintMember(current, env, locals);}
  if (current.type === 'CallExpression') {return taintCall(current, env, locals);}
  return { direct: false, viaUnknown: false };
}

function readTaint(env: ReadonlyMap<string, Taint>, name: string): Taint {
  return env.get(name) ?? { direct: false, viaUnknown: false };
}

function taintMember(current: TSESTree.MemberExpression, env: ReadonlyMap<string, Taint>, locals: ReadonlySet<string>): Taint {
  const objectTaint = taintOf(current.object, env, locals);
  if (objectTaint.direct || objectTaint.viaUnknown) {return objectTaint;}
  return { direct: false, viaUnknown: false };
}

function taintCall(current: TSESTree.CallExpression, env: ReadonlyMap<string, Taint>, locals: ReadonlySet<string>): Taint {
  const callee = stripNode(current.callee);
  const args = current.arguments.filter((arg): arg is TSESTree.Expression => arg.type !== 'SpreadElement');
  const argTaint = orAll(args, env, locals);
  if (isUnknownCallee(callee, locals) && (argTaint.direct || argTaint.viaUnknown)) {
    return { direct: false, viaUnknown: true };
  }
  return { direct: false, viaUnknown: false };
}

function isUnknownCallee(callee: TSESTree.Node, locals: ReadonlySet<string>): boolean {
  return callee.type === 'Identifier' && !locals.has(callee.name) && !BUILTINS.has(callee.name) && callee.name !== 'eval';
}

function orAll(nodes: readonly TSESTree.Node[], env: ReadonlyMap<string, Taint>, locals: ReadonlySet<string>): Taint {
  let acc: Taint = { direct: false, viaUnknown: false };
  for (const node of nodes) {acc = orTaint(acc, taintOf(node, env, locals));}
  return acc;
}

function orTaint(left: Taint, right: Taint): Taint {
  return { direct: left.direct || right.direct, viaUnknown: left.viaUnknown || right.viaUnknown };
}
