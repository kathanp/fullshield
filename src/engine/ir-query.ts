import { REQUEST_SOURCE_PROPS } from '../modules/sast/ast.js';
import type { IrNode, IrQueryFinding, ModuleIr } from './ir-types.js';

interface Flow {
  tainted: Set<number>;
  label: Map<number, string>;
  /** SSA ids that are the unbound or parameter name `req` (not a later assignment). */
  reqIds: Set<number>;
  /** SSA ids of `req.query` / `req.body` / `req.params` / `req.headers` / `req.files`. */
  requestObjects: Set<number>;
}

/**
 * One source→sink query: request properties flow to a call named `query`.
 * Property stores taint the whole object. Per-field precision is phase 252.
 * Each function has its own SSA ids, so closure capture across functions is not joined.
 */
export function queryModule(ir: ModuleIr): IrQueryFinding[] {
  const findings: IrQueryFinding[] = [];
  for (const fn of ir.functions) {
    queryFunction(fn.nodes, findings);
  }
  return findings;
}

function queryFunction(nodes: readonly IrNode[], findings: IrQueryFinding[]): void {
  const flow: Flow = {
    tainted: new Set(),
    label: new Map(),
    reqIds: new Set(),
    requestObjects: new Set(),
  };
  for (const node of nodes) {
    step(node, flow, findings);
  }
}

function step(node: IrNode, flow: Flow, findings: IrQueryFinding[]): void {
  if (node.op === 'assign') {
    assign(node, flow);
    return;
  }
  if (node.op === 'property-load') {
    load(node, flow);
    return;
  }
  if (node.op === 'property-store') {
    store(node, flow);
    return;
  }
  if (node.op === 'call') {
    call(node, flow, findings);
    return;
  }
  if ((node.op === 'await' || node.op === 'phi') && node.dest !== undefined) {
    copyTaint(flow, node.dest, node.args ?? []);
  }
}

function assign(node: IrNode, flow: Flow): void {
  const dest = node.dest;
  if ('literal' in node) {return;}
  if (dest !== undefined && node.name === 'req' && (node.args === undefined || node.args.length === 0)) {
    flow.reqIds.add(dest);
  }
  if (dest === undefined) {return;}
  copyTaint(flow, dest, node.args ?? []);
}

function load(node: IrNode, flow: Flow): void {
  const dest = node.dest;
  const obj = node.args?.[0];
  if (dest === undefined || obj === undefined) {return;}
  const prop = node.name;
  if (prop !== undefined && flow.reqIds.has(obj) && REQUEST_SOURCE_PROPS.has(prop)) {
    flow.tainted.add(dest);
    flow.requestObjects.add(dest);
    flow.label.set(dest, `req.${prop}`);
    return;
  }
  if (flow.requestObjects.has(obj)) {
    flow.tainted.add(dest);
    const base = flow.label.get(obj) ?? 'req';
    flow.label.set(dest, extend(base, prop));
    return;
  }
  if (flow.tainted.has(obj)) {
    flow.tainted.add(dest);
    const base = flow.label.get(obj);
    if (base !== undefined) {flow.label.set(dest, extend(base, prop));}
  }
}

function store(node: IrNode, flow: Flow): void {
  const obj = node.args?.[0];
  const value = node.args?.[1];
  if (obj === undefined || value === undefined || !flow.tainted.has(value)) {return;}
  flow.tainted.add(obj);
  const label = flow.label.get(value);
  if (label !== undefined && !flow.label.has(obj)) {flow.label.set(obj, label);}
}

function call(node: IrNode, flow: Flow, findings: IrQueryFinding[]): void {
  const args = node.args ?? [];
  if (node.name === 'query') {
    const hit = args.find((id) => flow.tainted.has(id));
    if (hit !== undefined) {
      findings.push({
        file: node.file,
        line: node.line,
        col: node.col,
        sink: 'query',
        source: flow.label.get(hit) ?? 'tainted',
      });
    }
  }
  if (node.dest !== undefined) {copyTaint(flow, node.dest, args);}
}

function copyTaint(flow: Flow, dest: number, args: readonly number[]): void {
  for (const arg of args) {
    if (!flow.tainted.has(arg)) {continue;}
    flow.tainted.add(dest);
    const label = flow.label.get(arg);
    if (label !== undefined) {flow.label.set(dest, label);}
    return;
  }
}

function extend(base: string, prop: string | undefined): string {
  if (prop === undefined || prop === '<dynamic>' || prop === '*') {return base;}
  return `${base}.${prop}`;
}
