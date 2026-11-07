import { readFile } from 'node:fs/promises';
import { isAbsolute, join, posix, relative } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import { makeFindingId, type Finding } from '../../core/finding.js';
import { attachParents, boundNames, calleeName, isFunctionNode, propName, walk } from '../sast/ast.js';
import { parseSource } from '../sast/fileScan.js';
import type { AstNode } from '../sast/types.js';

export const AGENTS_FLAG = 'FULLSHIELD_EXPERIMENTAL_AGENTS';

const MAX_HOPS = 5;
const SOURCE_PROPS = new Set(['body', 'query', 'params', 'headers', 'cookies']);
const SHELL = new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']);
const FILE_WRITE = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync']);
const SQL = new Set(['query', 'execute']);

export interface AgentSource {
  file: string;
  source: string;
}

interface Fn {
  file: string;
  name: string;
  node: AstNode;
  params: string[];
}

interface Seed {
  file: string;
  name: string;
  param: string;
  depth: number;
  shell: boolean;
}

interface Parsed {
  file: string;
  ast: AstNode;
  functions: Fn[];
  imports: Map<string, { file: string; name: string }>;
}

function skipped(file: string): boolean {
  const norm = file.split('\\').join('/');
  if (norm.startsWith('/') || isAbsolute(norm) || norm.split('/').includes('..')) {return true;}
  const parts = norm.split('/');
  if (parts.includes('.cursor')) {return true;}
  return parts[parts.length - 1] === 'SKILL.md';
}

function keyName(node: AstNode): string | undefined {
  if (node.type !== 'Property') {return undefined;}
  if (node.key.type === 'Identifier' && node.computed !== true) {return node.key.name;}
  if (node.key.type === 'Literal' && typeof node.key.value === 'string') {return node.key.value;}
  return undefined;
}

function lineOf(node: AstNode): number {
  return node.loc?.start.line ?? 1;
}

function finding(ruleId: string, title: string, message: string, file: string, line: number, cwe: string): Finding {
  return {
    id: makeFindingId(ruleId, file, String(line)),
    ruleId,
    module: 'agents',
    title,
    severity: 'high',
    confidence: 'medium',
    cwe,
    file,
    line,
    message,
    remediation: 'Keep user text in the user role. Do not place it in a system message or a tool argument. A tool handler must not pass that argument to a shell, a file write, or SQL.',
  };
}

function isRequestSource(node: AstNode): boolean {
  if (node.type !== 'MemberExpression') {return false;}
  const name = propName(node);
  if (node.object.type === 'Identifier' && node.object.name === 'req' && name !== undefined && SOURCE_PROPS.has(name)) {
    return true;
  }
  return node.object.type === 'MemberExpression' && isRequestSource(node.object);
}

function exprKey(node: AstNode | undefined): string | undefined {
  if (node === undefined) {return undefined;}
  if (node.type === 'Identifier') {return node.name;}
  if (node.type === 'MemberExpression' && !node.computed && node.object.type === 'Identifier') {
    const name = propName(node);
    return name === undefined ? undefined : `${node.object.name}.${name}`;
  }
  return undefined;
}

function exprTainted(node: AstNode | undefined, tainted: ReadonlySet<string>): boolean {
  if (node === undefined || node.type === 'SpreadElement') {return false;}
  if (node.type === 'Identifier') {return tainted.has(node.name);}
  if (node.type === 'MemberExpression') {
    if (isRequestSource(node)) {return true;}
    if (node.object.type === 'Identifier' && tainted.has(node.object.name)) {return true;}
    return exprTainted(node.object, tainted);
  }
  if (node.type === 'BinaryExpression') {
    return exprTainted(node.left, tainted) || exprTainted(node.right, tainted);
  }
  if (node.type === 'TemplateLiteral') {
    return node.expressions.some((item) => exprTainted(item, tainted));
  }
  if (node.type === 'CallExpression' && calleeName(node) === 'stringify') {
    return node.arguments.some((arg) => exprTainted(arg, tainted));
  }
  return false;
}

function addNames(node: AstNode | undefined, into: Set<string>): void {
  if (node === undefined) {return;}
  for (const name of boundNames(node)) {into.add(name);}
}

function propagate(root: AstNode, initial: ReadonlySet<string>): Set<string> {
  const tainted = new Set(initial);
  let grew = true;
  while (grew) {
    const before = tainted.size;
    walk(root, (node) => {
      if (node.type !== 'VariableDeclarator' || node.init === null || node.init === undefined) {return;}
      if (exprTainted(node.init, tainted) || isRequestSource(node.init)) {addNames(node.id, tainted);}
      if (node.id.type === 'ObjectPattern' && node.init.type === 'Identifier' && tainted.has(node.init.name)) {
        addNames(node.id, tainted);
      }
    });
    grew = tainted.size > before;
  }
  return tainted;
}

function requestNames(ast: AstNode): Set<string> {
  const seeds = new Set<string>();
  walk(ast, (node) => {
    if (node.type === 'VariableDeclarator' && node.init !== null && isRequestSource(node.init)) {
      addNames(node.id, seeds);
    }
  });
  return propagate(ast, seeds);
}

function blockReturns(node: AstNode): boolean {
  if (node.type === 'ReturnStatement' || node.type === 'ThrowStatement') {return true;}
  if (node.type !== 'BlockStatement') {return false;}
  return node.body.some((stmt) => stmt.type === 'ReturnStatement' || stmt.type === 'ThrowStatement');
}

function guardedKeys(root: AstNode): Set<string> {
  const keys = new Set<string>();
  walk(root, (node) => {
    if (node.type !== 'IfStatement') {return;}
    const test = node.test.type === 'UnaryExpression' && node.test.operator === '!' ? node.test.argument : node.test;
    if (test.type !== 'CallExpression') {return;}
    const name = calleeName(test);
    if (name !== 'includes' && name !== 'has') {return;}
    if (!blockReturns(node.consequent)) {return;}
    const arg = test.arguments[0];
    const key = arg === undefined ? undefined : exprKey(arg);
    if (key !== undefined) {keys.add(key);}
  });
  return keys;
}

function objectProp(node: AstNode, name: string): AstNode | undefined {
  if (node.type !== 'ObjectExpression') {return undefined;}
  for (const prop of node.properties) {
    if (prop.type === 'Property' && keyName(prop) === name) {return prop.value;}
  }
  return undefined;
}

function collectSinks(file: string, root: AstNode, tainted: ReadonlySet<string>, shell: boolean, out: Finding[]): void {
  const guards = guardedKeys(root);
  walk(root, (node) => {
    if (node.type === 'ObjectExpression') {
      const role = objectProp(node, 'role');
      const content = objectProp(node, 'content');
      if (role?.type === 'Literal' && role.value === 'system' && exprTainted(content, tainted)) {
        out.push(finding(
          'AGENTS-SYSTEM-001',
          'Untrusted input in a system message',
          'Request data reaches a system-role message.',
          file,
          lineOf(node),
          'CWE-1426',
        ));
      }
      const args = objectProp(node, 'arguments') ?? objectProp(node, 'parameters');
      const named = objectProp(node, 'name') !== undefined;
      const parent = (node as AstNode & { parent?: AstNode }).parent;
      const parentName = parent?.type === 'Property' ? keyName(parent) : undefined;
      const toolArg = named || parentName === 'tools' || parentName === 'functions' || parentName === 'function';
      if (toolArg && exprTainted(args, tainted)) {
        out.push(finding(
          'AGENTS-TOOL-001',
          'Untrusted input in a tool argument',
          'Request data reaches a tool or function argument.',
          file,
          lineOf(node),
          'CWE-1426',
        ));
      }
    }
    if (!shell || node.type !== 'CallExpression') {return;}
    const name = calleeName(node);
    if (name === undefined) {return;}
    const kind = SHELL.has(name) ? 'shell' : FILE_WRITE.has(name) ? 'file write' : SQL.has(name) ? 'SQL' : undefined;
    if (kind === undefined) {return;}
    const arg = node.arguments[0];
    if (arg === undefined || arg.type === 'SpreadElement' || arg.type === 'Literal') {return;}
    const key = exprKey(arg);
    if (key !== undefined && guards.has(key)) {return;}
    if (!exprTainted(arg, tainted)) {return;}
    out.push(finding(
      'AGENTS-SINK-001',
      'Tool handler forwards its argument to a sink',
      `A registered tool handler passes its argument to a ${kind}.`,
      file,
      lineOf(node),
      kind === 'SQL' ? 'CWE-89' : kind === 'file write' ? 'CWE-73' : 'CWE-78',
    ));
  });
}

function functionsIn(file: string, ast: AstNode): Fn[] {
  const found: Fn[] = [];
  const push = (name: string | undefined, node: AstNode): void => {
    if (name === undefined || name.length === 0 || !isFunctionNode(node)) {return;}
    const params = node.params.flatMap((param) => boundNames(param));
    found.push({ file, name, node, params });
  };
  walk(ast, (node) => {
    if (node.type === 'FunctionDeclaration') {push(node.id?.name, node);}
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init !== null && isFunctionNode(node.init)) {
      push(node.id.name, node.init);
    }
    if (node.type === 'Property' && isFunctionNode(node.value)) {push(keyName(node), node.value);}
    if (node.type === 'CallExpression') {
      const name = calleeName(node);
      const last = node.arguments[node.arguments.length - 1];
      if ((name === 'tool' || name === 'registerTool' || name === 'addTool') && last !== undefined && isFunctionNode(last)) {
        push(`__handler_${lineOf(last)}`, last);
      }
    }
  });
  return found;
}

function importMap(file: string, ast: AstNode, files: ReadonlySet<string>): Map<string, { file: string; name: string }> {
  const map = new Map<string, { file: string; name: string }>();
  const resolve = (spec: string): string | undefined => {
    if (!spec.startsWith('.')) {return undefined;}
    const base = posix.normalize(posix.join(posix.dirname(file), spec));
    for (const candidate of [base, `${base}.js`, `${base}.ts`, `${base}.mjs`, `${base}.cjs`]) {
      if (files.has(candidate)) {return candidate;}
    }
    return undefined;
  };
  const bind = (local: string, spec: string, name: string): void => {
    const target = resolve(spec);
    if (target !== undefined) {map.set(local, { file: target, name });}
  };
  walk(ast, (node) => {
    if (node.type === 'ImportDeclaration' && typeof node.source.value === 'string') {
      for (const spec of node.specifiers) {
        if (spec.type === 'ImportSpecifier' && spec.imported.type === 'Identifier') {
          bind(spec.local.name, node.source.value, spec.imported.name);
        }
      }
    }
    if (node.type !== 'VariableDeclarator' || node.init === null || node.init.type !== 'CallExpression') {return;}
    if (calleeName(node.init) !== 'require' || node.init.arguments[0]?.type !== 'Literal') {return;}
    const spec = node.init.arguments[0];
    if (spec.type !== 'Literal' || typeof spec.value !== 'string' || node.id.type !== 'ObjectPattern') {return;}
    for (const prop of node.id.properties) {
      if (prop.type === 'Property' && prop.key.type === 'Identifier' && prop.value.type === 'Identifier') {
        bind(prop.value.name, spec.value, prop.key.name);
      }
    }
  });
  return map;
}

function toolHandlers(ast: AstNode): AstNode[] {
  const handlers: AstNode[] = [];
  walk(ast, (node) => {
    if (node.type === 'CallExpression') {
      const name = calleeName(node);
      const last = node.arguments[node.arguments.length - 1];
      if ((name === 'tool' || name === 'registerTool' || name === 'addTool') && last !== undefined && isFunctionNode(last)) {
        handlers.push(last);
      }
    }
    if (node.type === 'Property' && (keyName(node) === 'execute' || keyName(node) === 'handler') && isFunctionNode(node.value)) {
      const parent = (node as AstNode & { parent?: AstNode }).parent;
      const named = parent?.type === 'ObjectExpression' && parent.properties.some((prop) => prop.type === 'Property' && keyName(prop) === 'name');
      if (named) {handlers.push(node.value);}
    }
  });
  return handlers;
}

function resolveCallee(name: string, parsed: Parsed, all: ReadonlyMap<string, Fn>): Fn | undefined {
  const local = all.get(`${parsed.file}#${name}`);
  if (local !== undefined) {return local;}
  const imported = parsed.imports.get(name);
  return imported === undefined ? undefined : all.get(`${imported.file}#${imported.name}`);
}

function callsOut(parsed: Parsed, root: AstNode, tainted: ReadonlySet<string>, all: ReadonlyMap<string, Fn>): Array<{ fn: Fn; param: string }> {
  const out: Array<{ fn: Fn; param: string }> = [];
  walk(root, (node) => {
    if (node.type !== 'CallExpression' || node.callee.type !== 'Identifier') {return;}
    const fn = resolveCallee(node.callee.name, parsed, all);
    const arg = node.arguments[0];
    const param = fn?.params[0];
    if (fn === undefined || param === undefined || arg === undefined || !exprTainted(arg, tainted)) {return;}
    out.push({ fn, param });
  });
  return out;
}

export async function scanAgentsSources(files: readonly AgentSource[]): Promise<Finding[]> {
  const parsed: Parsed[] = [];
  for (const file of files) {
    if (skipped(file.file) || !/\.[cm]?[jt]sx?$/.test(file.file)) {continue;}
    const ast = await parseSource(file.source);
    if (ast === null) {continue;}
    attachParents(ast);
    parsed.push({
      file: file.file,
      ast,
      functions: functionsIn(file.file, ast),
      imports: new Map(),
    });
  }
  const names = new Set(parsed.map((file) => file.file));
  for (const file of parsed) {file.imports = importMap(file.file, file.ast, names);}
  const all = new Map<string, Fn>();
  for (const file of parsed) {
    for (const fn of file.functions) {all.set(`${fn.file}#${fn.name}`, fn);}
  }
  const byFile = new Map(parsed.map((file) => [file.file, file]));
  const found: Finding[] = [];
  const queue: Seed[] = [];
  for (const file of parsed) {
    const tainted = requestNames(file.ast);
    collectSinks(file.file, file.ast, tainted, false, found);
    for (const call of callsOut(file, file.ast, tainted, all)) {
      queue.push({ file: call.fn.file, name: call.fn.name, param: call.param, depth: 1, shell: false });
    }
    for (const handler of toolHandlers(file.ast)) {
      const match = file.functions.find((fn) => fn.node === handler);
      const param = match?.params[0];
      if (match !== undefined && param !== undefined) {
        queue.push({ file: file.file, name: match.name, param, depth: 0, shell: true });
      }
    }
  }
  const seen = new Set<string>();
  while (queue.length > 0) {
    const seed = queue.shift();
    if (seed === undefined || seed.depth > MAX_HOPS) {continue;}
    const key = `${seed.file}#${seed.name}#${seed.param}#${seed.depth}#${seed.shell}`;
    if (seen.has(key)) {continue;}
    seen.add(key);
    const fn = all.get(`${seed.file}#${seed.name}`);
    const file = byFile.get(seed.file);
    if (fn === undefined || file === undefined) {continue;}
    const base = requestNames(file.ast);
    base.add(seed.param);
    const tainted = propagate(fn.node, base);
    collectSinks(seed.file, fn.node, tainted, seed.shell, found);
    if (seed.depth === MAX_HOPS) {continue;}
    for (const call of callsOut(file, fn.node, tainted, all)) {
      queue.push({
        file: call.fn.file,
        name: call.fn.name,
        param: call.param,
        depth: seed.depth + 1,
        shell: seed.shell,
      });
    }
  }
  const uniq = new Map<string, Finding>();
  for (const item of found) {uniq.set(`${item.ruleId}|${item.file}|${item.line}`, item);}
  return [...uniq.values()];
}

export const agentsModule: ScanModule = {
  name: 'agents',
  async run(ctx) {
    if (process.env[AGENTS_FLAG] !== '1') {return [];}
    const sources: AgentSource[] = [];
    for (const file of ctx.files) {
      if (skipped(file)) {continue;}
      const abs = join(ctx.cwd, file);
      const rel = relative(ctx.cwd, abs);
      if (rel.startsWith('..') || isAbsolute(rel)) {continue;}
      sources.push({ file: file.split('\\').join('/'), source: await readFile(abs, 'utf8') });
    }
    return scanAgentsSources(sources);
  },
};
