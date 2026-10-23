import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { parseProgram, lineOf, propName, stripNode, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_POINTSTO';

const DEFAULT_BUDGET = 2_000_000;

export interface PointsToCall {
  line: number;
  sink: boolean;
  targetKinds: string[];
}

export interface PointsToFinding {
  file: string;
  line: number;
  sink: string;
}

export interface PointsToResult {
  findings: PointsToFinding[];
  events: UnsoundEvent[];
  calls: PointsToCall[];
  variables: Record<string, string[]>;
}

export interface PointsToOptions {
  file?: string;
  budget?: number;
}

type LocKind = 'pool' | 'object' | 'ctor-pool' | 'ctor-user' | 'unknown';

interface FieldBind {
  prop: string;
  paramIndex: number;
}

type Constraint =
  | { op: 'alloc'; dst: string; loc: string }
  | { op: 'copy'; dst: string; src: string }
  | { op: 'load'; dst: string; objVar: string; field: string }
  | { op: 'obj-field'; loc: string; field: string; src: string }
  | { op: 'invoke-new'; dst: string; callee: string; args: string[]; site: string }
  | { op: 'call-ret'; dst: string; fn: string }
  | { op: 'unknown-var'; dst: string };

interface RecordedCall {
  line: number;
  objVar: string;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzePointsTo(source: string, options?: PointsToOptions): PointsToResult {
  const empty: PointsToResult = { findings: [], events: [], calls: [], variables: {} };
  if (!enabled()) {return empty;}
  const program = parseProgram(source);
  if (program === null) {return empty;}
  const file = options?.file ?? 'inline.js';
  const budget = options?.budget ?? DEFAULT_BUDGET;
  const built = build(program);
  if (built.constraints.length > budget) {return budgetResult(built, file);}
  solve(built);
  return solvedResult(built, file);
}

function budgetResult(built: Model, file: string): PointsToResult {
  const variables: Record<string, string[]> = {};
  for (const name of built.declared) {
    if (isUserVar(name)) {variables[name] = ['unknown'];}
  }
  return {
    findings: [],
    events: [{ kind: 'fixpoint-cap', file, line: 1, reason: 'points-to budget' }],
    calls: built.calls.map((call) => ({ line: call.line, sink: false, targetKinds: ['unknown'] })),
    variables,
  };
}

function isUserVar(name: string): boolean {
  return !name.includes(':') && !name.startsWith('t');
}

function solvedResult(built: Model, file: string): PointsToResult {
  const calls: PointsToCall[] = [];
  const findings: PointsToFinding[] = [];
  for (const call of built.calls) {recordSolvedCall(call, built, file, calls, findings);}
  return { findings, events: built.events, calls, variables: variableMap(built) };
}

function recordSolvedCall(
  call: RecordedCall,
  built: Model,
  file: string,
  calls: PointsToCall[],
  findings: PointsToFinding[],
): void {
  const locs = built.pt.get(call.objVar) ?? new Set<string>();
  const targetKinds = kindsOf(locs, built.locKind);
  const sink = [...locs].some((loc) => isPoolSink(loc, built));
  calls.push({ line: call.line, sink, targetKinds });
  if (sink) {findings.push({ file, line: call.line, sink: 'pg.Pool.query' });}
}

function isPoolSink(loc: string, built: Model): boolean {
  return built.locKind.get(loc) === 'pool' || built.methods.get(loc)?.get('query') === 'sink';
}

function variableMap(built: Model): Record<string, string[]> {
  const variables: Record<string, string[]> = {};
  for (const name of [...built.pt.keys()].sort()) {
    if (isHiddenVar(name)) {continue;}
    variables[name] = [...(built.pt.get(name) ?? [])].sort();
  }
  return variables;
}

function isHiddenVar(name: string): boolean {
  return name.startsWith('t') || name.startsWith('return:');
}

interface Model {
  constraints: Constraint[];
  pt: Map<string, Set<string>>;
  fields: Map<string, Map<string, Set<string>>>;
  locKind: Map<string, LocKind>;
  methods: Map<string, Map<string, 'sink' | 'user'>>;
  ctorFields: Map<string, FieldBind[]>;
  declared: Set<string>;
  calls: RecordedCall[];
  events: UnsoundEvent[];
  temps: number;
  currentFn: string;
}

function build(program: TSESTree.Program): Model {
  const model: Model = {
    constraints: [],
    pt: new Map(),
    fields: new Map(),
    locKind: new Map([['unknown', 'unknown']]),
    methods: new Map(),
    ctorFields: new Map(),
    declared: new Set(),
    calls: [],
    events: [],
    temps: 0,
    currentFn: '',
  };
  collectCtors(program, model);
  for (const stmt of program.body) {walkStmt(stmt, model);}
  return model;
}

function collectCtors(program: TSESTree.Program, model: Model): void {
  for (const stmt of program.body) {
    if (stmt.type === 'FunctionDeclaration' && stmt.id !== null) {
      const loc = `ctor:${stmt.id.name}`;
      model.locKind.set(loc, 'ctor-user');
      model.ctorFields.set(loc, thisFields(stmt));
    }
    if (stmt.type === 'ClassDeclaration' && stmt.id !== null) {
      const ctor = stmt.body.body.find((member) => member.type === 'MethodDefinition' && member.kind === 'constructor');
      const loc = `ctor:${stmt.id.name}`;
      model.locKind.set(loc, 'ctor-user');
      if (ctor !== undefined && ctor.type === 'MethodDefinition' && ctor.value.type === 'FunctionExpression') {
        model.ctorFields.set(loc, thisFields(ctor.value));
      } else {
        model.ctorFields.set(loc, []);
      }
    }
  }
}

function thisFields(fn: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression): FieldBind[] {
  const params = fn.params.flatMap((param) => (param.type === 'Identifier' ? [param.name] : []));
  const fields: FieldBind[] = [];
  const body = fn.body.type === 'BlockStatement' ? fn.body.body : [];
  for (const stmt of body) {
    if (stmt.type !== 'ExpressionStatement' || stmt.expression.type !== 'AssignmentExpression') {continue;}
    const { left, right } = stmt.expression;
    if (left.type !== 'MemberExpression' || left.object.type !== 'ThisExpression') {continue;}
    if (right.type !== 'Identifier') {continue;}
    const prop = propName(left);
    const paramIndex = params.indexOf(right.name);
    if (prop === null || paramIndex < 0) {continue;}
    fields.push({ prop, paramIndex });
  }
  return fields;
}

function walkStmt(stmt: TSESTree.Statement, model: Model): void {
  if (stmt.type === 'FunctionDeclaration' && stmt.id !== null) {walkFunction(stmt, model); return;}
  if (stmt.type === 'ClassDeclaration' && stmt.id !== null) {walkClass(stmt, model); return;}
  if (stmt.type === 'VariableDeclaration') {
    for (const decl of stmt.declarations) {bindDeclarator(decl, model);}
    return;
  }
  if (stmt.type === 'ExpressionStatement') {walkExpression(stmt, model); return;}
  if (stmt.type === 'IfStatement') {walkIf(stmt, model); return;}
  if (stmt.type === 'BlockStatement') {walkBlock(stmt.body, model); return;}
  walkReturn(stmt, model);
}

function walkFunction(stmt: TSESTree.FunctionDeclaration, model: Model): void {
  if (stmt.id === null) {return;}
  const loc = `ctor:${stmt.id.name}`;
  model.declared.add(stmt.id.name);
  model.constraints.push({ op: 'alloc', dst: stmt.id.name, loc });
  const prev = model.currentFn;
  model.currentFn = stmt.id.name;
  walkBlock(stmt.body.body, model);
  model.currentFn = prev;
}

function walkClass(stmt: TSESTree.ClassDeclaration, model: Model): void {
  if (stmt.id === null) {return;}
  model.declared.add(stmt.id.name);
  model.constraints.push({ op: 'alloc', dst: stmt.id.name, loc: `ctor:${stmt.id.name}` });
}

function walkExpression(stmt: TSESTree.ExpressionStatement, model: Model): void {
  const expr = stripNode(stmt.expression);
  if (expr.type === 'AssignmentExpression' && expr.left.type === 'Identifier') {
    const dst = bindName(expr.left.name, model);
    model.constraints.push({ op: 'copy', dst, src: ensureVar(expr.right, model) });
  }
  if (expr.type === 'CallExpression') {recordQuery(expr, model);}
}

function walkIf(stmt: TSESTree.IfStatement, model: Model): void {
  walkStmt(stmt.consequent, model);
  if (stmt.alternate !== null) {walkStmt(stmt.alternate, model);}
}

function walkReturn(stmt: TSESTree.Statement, model: Model): void {
  if (stmt.type === 'ReturnStatement' && stmt.argument !== null && model.currentFn !== '') {
    const ret = `return:${model.currentFn}`;
    model.constraints.push({ op: 'copy', dst: ret, src: ensureVar(stmt.argument, model) });
  }
}

function walkBlock(body: readonly TSESTree.Statement[], model: Model): void {
  for (const stmt of body) {walkStmt(stmt, model);}
}

function bindDeclarator(decl: TSESTree.VariableDeclarator, model: Model): void {
  if (decl.id.type === 'ObjectPattern' && decl.init !== null && isRequire(decl.init, 'pg')) {
    for (const prop of decl.id.properties) {
      if (prop.type !== 'Property' || prop.key.type !== 'Identifier' || prop.value.type !== 'Identifier') {continue;}
      if (prop.key.name !== 'Pool' && prop.key.name !== 'Client') {continue;}
      const dst = bindName(prop.value.name, model);
      model.locKind.set('ctor:pg.Pool', 'ctor-pool');
      model.constraints.push({ op: 'alloc', dst, loc: 'ctor:pg.Pool' });
    }
    return;
  }
  if (decl.id.type === 'Identifier' && decl.init !== null) {
    const dst = bindName(decl.id.name, model);
    model.constraints.push({ op: 'copy', dst, src: ensureVar(decl.init, model) });
  }
}

function bindName(name: string, model: Model): string {
  const key = model.currentFn === '' ? name : `${model.currentFn}:${name}`;
  model.declared.add(key);
  return key;
}

function resolveName(name: string, model: Model): string {
  const local = `${model.currentFn}:${name}`;
  if (model.currentFn !== '' && model.declared.has(local)) {return local;}
  return name;
}

function fresh(model: Model): string {
  model.temps += 1;
  return `t${String(model.temps)}`;
}

function ensureVar(node: TSESTree.Node, model: Model): string {
  const current = stripNode(node);
  if (current.type === 'Identifier') {return resolveName(current.name, model);}
  const dst = fresh(model);
  if (current.type === 'MemberExpression') {return ensureMember(current, dst, model);}
  if (current.type === 'NewExpression') {return ensureNew(current, dst, model);}
  if (current.type === 'ObjectExpression') {return ensureObject(current, dst, model);}
  if (current.type === 'CallExpression') {return ensureCall(current, dst, model);}
  model.constraints.push({ op: 'unknown-var', dst });
  return dst;
}

function ensureMember(current: TSESTree.MemberExpression, dst: string, model: Model): string {
  const field = propName(current);
  const objVar = ensureVar(current.object, model);
  if (field === null) {model.constraints.push({ op: 'unknown-var', dst });}
  else {model.constraints.push({ op: 'load', dst, objVar, field });}
  return dst;
}

function ensureNew(current: TSESTree.NewExpression, dst: string, model: Model): string {
  const args = current.arguments.flatMap((arg) => (arg.type === 'SpreadElement' ? [] : [ensureVar(arg, model)]));
  model.constraints.push({
    op: 'invoke-new',
    dst,
    callee: ensureVar(current.callee, model),
    args,
    site: `new:${String(lineOf(current))}:${dst}`,
  });
  return dst;
}

function ensureObject(current: TSESTree.ObjectExpression, dst: string, model: Model): string {
  const loc = `obj:${String(lineOf(current))}:${dst}`;
  model.locKind.set(loc, 'object');
  model.constraints.push({ op: 'alloc', dst, loc });
  for (const prop of current.properties) {bindObjectProp(prop, loc, model);}
  return dst;
}

function bindObjectProp(prop: TSESTree.ObjectLiteralElement, loc: string, model: Model): void {
  if (prop.type !== 'Property' || prop.key.type !== 'Identifier') {return;}
  const isMethod = prop.method || prop.value.type === 'FunctionExpression' || prop.value.type === 'ArrowFunctionExpression';
  if (isMethod) {
    const table = model.methods.get(loc) ?? new Map<string, 'sink' | 'user'>();
    table.set(prop.key.name, 'user');
    model.methods.set(loc, table);
    return;
  }
  model.constraints.push({ op: 'obj-field', loc, field: prop.key.name, src: ensureVar(prop.value, model) });
}

function ensureCall(current: TSESTree.CallExpression, dst: string, model: Model): string {
  if (isRequire(current, 'pg')) {return ensurePg(dst, model);}
  if (current.callee.type === 'Identifier') {
    model.constraints.push({ op: 'call-ret', dst, fn: current.callee.name });
    recordQuery(current, model);
    return dst;
  }
  model.constraints.push({ op: 'unknown-var', dst });
  return dst;
}

function ensurePg(dst: string, model: Model): string {
  const loc = 'mod:pg';
  model.locKind.set(loc, 'object');
  model.locKind.set('ctor:pg.Pool', 'ctor-pool');
  seedField(model, loc, 'Pool', 'ctor:pg.Pool');
  model.constraints.push({ op: 'alloc', dst, loc });
  return dst;
}

function recordQuery(call: TSESTree.CallExpression, model: Model): void {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression' || propName(callee) !== 'query') {return;}
  model.calls.push({ line: lineOf(call), objVar: ensureVar(callee.object, model) });
}

function isRequire(node: TSESTree.Node, pkg: string): boolean {
  const current = stripNode(node);
  if (current.type !== 'CallExpression' || current.callee.type !== 'Identifier' || current.callee.name !== 'require') {return false;}
  const arg = current.arguments[0];
  return arg !== undefined && arg.type === 'Literal' && arg.value === pkg;
}

function seedField(model: Model, loc: string, field: string, target: string): void {
  const table = model.fields.get(loc) ?? new Map<string, Set<string>>();
  const set = table.get(field) ?? new Set<string>();
  set.add(target);
  table.set(field, set);
  model.fields.set(loc, table);
}

function solve(model: Model): void {
  for (let round = 0; round < 32; round += 1) {
    let changed = false;
    for (const constraint of model.constraints) {
      if (applyConstraint(constraint, model)) {changed = true;}
    }
    if (!changed) {return;}
    if (round === 31) {
      model.events.push({ kind: 'fixpoint-cap', file: 'inline.js', line: 1, reason: 'points-to budget' });
    }
  }
}

function applyConstraint(constraint: Constraint, model: Model): boolean {
  if (constraint.op === 'alloc') {return addPt(model, constraint.dst, constraint.loc);}
  if (constraint.op === 'copy') {return addSet(model, constraint.dst, model.pt.get(constraint.src) ?? new Set());}
  if (constraint.op === 'unknown-var') {return addPt(model, constraint.dst, 'unknown');}
  if (constraint.op === 'load') {
    let changed = false;
    for (const loc of model.pt.get(constraint.objVar) ?? []) {
      changed = addSet(model, constraint.dst, model.fields.get(loc)?.get(constraint.field) ?? new Set()) || changed;
    }
    return changed;
  }
  if (constraint.op === 'obj-field') {
    return addField(model, constraint.loc, constraint.field, model.pt.get(constraint.src) ?? new Set());
  }
  if (constraint.op === 'call-ret') {
    return addSet(model, constraint.dst, model.pt.get(`return:${constraint.fn}`) ?? new Set());
  }
  return applyNew(constraint, model);
}

function applyNew(constraint: Extract<Constraint, { op: 'invoke-new' }>, model: Model): boolean {
  let changed = false;
  for (const loc of model.pt.get(constraint.callee) ?? []) {
    const kind = model.locKind.get(loc);
    if (kind === 'ctor-pool') {
      const inst = `${constraint.site}:pool`;
      model.locKind.set(inst, 'pool');
      const table = model.methods.get(inst) ?? new Map<string, 'sink' | 'user'>();
      table.set('query', 'sink');
      model.methods.set(inst, table);
      changed = addPt(model, constraint.dst, inst) || changed;
    } else if (kind === 'ctor-user') {
      const inst = `${constraint.site}:user`;
      model.locKind.set(inst, 'object');
      changed = addPt(model, constraint.dst, inst) || changed;
      for (const field of model.ctorFields.get(loc) ?? []) {
        const arg = constraint.args[field.paramIndex];
        if (arg === undefined) {continue;}
        changed = addField(model, inst, field.prop, model.pt.get(arg) ?? new Set()) || changed;
      }
    }
  }
  return changed;
}

function addPt(model: Model, dst: string, loc: string): boolean {
  const set = model.pt.get(dst) ?? new Set<string>();
  if (set.has(loc)) {model.pt.set(dst, set); return false;}
  set.add(loc);
  model.pt.set(dst, set);
  return true;
}

function addSet(model: Model, dst: string, src: ReadonlySet<string>): boolean {
  let changed = false;
  for (const loc of src) {changed = addPt(model, dst, loc) || changed;}
  return changed;
}

function addField(model: Model, loc: string, field: string, src: ReadonlySet<string>): boolean {
  const table = model.fields.get(loc) ?? new Map<string, Set<string>>();
  const set = table.get(field) ?? new Set<string>();
  let changed = false;
  for (const id of src) {
    if (!set.has(id)) {set.add(id); changed = true;}
  }
  table.set(field, set);
  model.fields.set(loc, table);
  return changed;
}

function kindsOf(locs: ReadonlySet<string>, locKind: ReadonlyMap<string, LocKind>): string[] {
  const kinds = new Set<string>();
  for (const loc of locs) {kinds.add(locKind.get(loc) ?? 'unknown');}
  return [...kinds].sort();
}
