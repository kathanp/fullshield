import { posix } from 'node:path';

import { makeFindingId, type Finding } from '../../core/finding.js';
import { assignedNameOf, attachParents, boundNames, calleeName, isFunctionNode, literalString, propName, walk } from './ast.js';
import { taintV2Enabled } from './experimental.js';
import { analyzeFile, analyzeFunctionWithSeed, exprIsTainted, isSchemaValidatorCall, nodeIsTainted } from './taint.js';
import type { AstNode } from './types.js';

const MAX_HOPS = 5;

export interface ParsedSource {
  file: string;
  source: string;
  ast: AstNode;
}

interface FnInfo {
  file: string;
  name: string;
  node: AstNode;
  params: string[];
}

interface Seed {
  file: string;
  name: string;
  paramIndex: number;
  trace: Array<{ file: string; line?: number; note: string }>;
}

function collectFunctions(file: string, ast: AstNode): FnInfo[] {
  attachParents(ast);
  const out: FnInfo[] = [];
  const push = (node: AstNode, name: string | undefined): void => {
    if (name === undefined || name.length === 0) return;
    out.push({
      file,
      name,
      node,
      params: node.type === 'FunctionDeclaration' || isFunctionNode(node) ? boundNamesFromParams(node) : [],
    });
  };
  walk(ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id !== null) {
      push(node, node.id.name);
      return;
    }
    if (isFunctionNode(node)) {
      push(node, assignedNameOf(node));
    }
    if (
      node.type === 'AssignmentExpression' &&
      node.left.type === 'MemberExpression' &&
      node.left.object.type === 'ThisExpression' &&
      isFunctionNode(node.right)
    ) {
      push(node.right, propName(node.left));
    }
  });
  return out;
}

function boundNamesFromParams(node: AstNode): string[] {
  if (!isFunctionNode(node)) return [];
  return node.params.flatMap((p) => boundNames(p));
}

export function collectRequires(file: string, ast: AstNode, files: ReadonlySet<string>): Map<string, string> {
  /** local binding → resolved file or file#exportName */
  const ns = new Map<string, string>();
  const bind = (local: string, spec: string, exportName?: string): void => {
    const resolved = resolveRelative(file, spec, files);
    if (resolved === undefined) return;
    ns.set(local, exportName !== undefined ? `${resolved}#${exportName}` : resolved);
  };

  walk(ast, (node) => {
    if (node.type === 'ImportDeclaration') {
      const spec = literalString(node.source);
      if (spec === undefined) return;
      for (const s of node.specifiers) {
        if (s.type === 'ImportDefaultSpecifier' || s.type === 'ImportNamespaceSpecifier') {
          bind(s.local.name, spec);
        } else if (s.type === 'ImportSpecifier') {
          const imported = s.imported.type === 'Identifier' ? s.imported.name : undefined;
          bind(s.local.name, spec, imported);
        }
      }
      return;
    }
    if (node.type !== 'VariableDeclarator' || node.init === null) return;
    if (node.id.type !== 'Identifier' && node.id.type !== 'ObjectPattern') return;

    const req = requireCall(node.init);
    if (req !== undefined) {
      if (node.id.type === 'Identifier') bind(node.id.name, req.spec, req.exportName);
      if (node.id.type === 'ObjectPattern') {
        for (const prop of node.id.properties) {
          if (prop.type === 'Property' && prop.key.type === 'Identifier' && prop.value.type === 'Identifier') {
            bind(prop.value.name, req.spec, prop.key.name);
          }
        }
      }
    }
  });
  return ns;
}

function requireCall(node: AstNode): { spec: string; exportName?: string } | undefined {
  if (node.type === 'CallExpression') {
    if (node.callee.type !== 'Identifier' || node.callee.name !== 'require') return undefined;
    const spec = literalString(node.arguments[0]);
    return spec === undefined ? undefined : { spec };
  }
  if (node.type === 'MemberExpression' && node.object.type === 'CallExpression') {
    const inner = requireCall(node.object);
    const name = propName(node);
    if (inner === undefined || name === undefined) return undefined;
    return { spec: inner.spec, exportName: name };
  }
  return undefined;
}

function reexportsOf(ast: AstNode): Map<string, { spec: string; name: string }> {
  const out = new Map<string, { spec: string; name: string }>();
  walk(ast, (node) => {
    if (node.type !== 'ExportNamedDeclaration' || node.source === null || node.source === undefined) return;
    const spec = literalString(node.source);
    if (spec === undefined) return;
    for (const specNode of node.specifiers) {
      if (specNode.type !== 'ExportSpecifier') continue;
      const exported = specNode.exported.type === 'Identifier' ? specNode.exported.name : undefined;
      const local = specNode.local.type === 'Identifier' ? specNode.local.name : exported;
      if (exported !== undefined && local !== undefined) out.set(exported, { spec, name: local });
    }
  });
  return out;
}

function resolveRelative(fromFile: string, spec: string, files: ReadonlySet<string>): string | undefined {
  if (!spec.startsWith('.')) return undefined;
  const base = posix.normalize(posix.join(posix.dirname(fromFile), spec));
  const candidates = [base, `${base}.js`, `${base}.ts`, `${base}.mjs`, `${base}.cjs`, `${base}/index.js`, `${base}/index.ts`];
  return candidates.find((c) => files.has(c));
}

function collectInstances(ast: AstNode, ns: Map<string, string>): Map<string, string> {
  const instances = new Map<string, string>();
  walk(ast, (node) => {
    if (node.type !== 'VariableDeclarator' || node.init === null) return;
    if (node.id.type !== 'Identifier' || node.init.type !== 'NewExpression') return;
    if (node.init.callee.type !== 'Identifier') return;
    const hit = ns.get(node.init.callee.name);
    if (hit === undefined) return;
    instances.set(node.id.name, hit.includes('#') ? (hit.split('#')[0] ?? hit) : hit);
  });
  return instances;
}

function resolveCallee(
  node: AstNode,
  ns: Map<string, string>,
  instances: Map<string, string>,
  currentFile: string,
  functions: Map<string, FnInfo>,
): { file: string; name: string } | undefined {
  if (node.type !== 'CallExpression') return undefined;
  if (node.callee.type === 'Identifier') {
    const hit = ns.get(node.callee.name);
    if (hit !== undefined) {
      if (hit.includes('#')) {
        const [file, name] = hit.split('#');
        if (file !== undefined && name !== undefined) return { file, name };
      }
      return { file: hit, name: node.callee.name };
    }
    if (functions.has(`${currentFile}#${node.callee.name}`)) {
      return { file: currentFile, name: node.callee.name };
    }
    return undefined;
  }
  if (node.callee.type === 'MemberExpression' && node.callee.object.type === 'Identifier') {
    const name = calleeName(node);
    if (name === undefined) return undefined;
    const instFile = instances.get(node.callee.object.name);
    if (instFile !== undefined) return { file: instFile, name };
    const file = ns.get(node.callee.object.name);
    if (file !== undefined && !file.includes('#')) return { file, name };
  }
  return undefined;
}

function isSqlSink(node: AstNode): boolean {
  if (node.type !== 'CallExpression') return false;
  const name = calleeName(node);
  return name === 'query' || name === 'execute';
}

function isCmdSink(node: AstNode): boolean {
  if (node.type !== 'CallExpression') return false;
  const name = calleeName(node);
  return name === 'exec' || name === 'execSync' || name === 'spawn' || name === 'spawnSync';
}

function whereValue(node: AstNode): AstNode | undefined {
  if (node.type !== 'ObjectExpression') return undefined;
  for (const prop of node.properties) {
    if (prop.type !== 'Property') continue;
    const key =
      prop.key.type === 'Identifier'
        ? prop.key.name
        : prop.key.type === 'Literal' && typeof prop.key.value === 'string'
          ? prop.key.value
          : undefined;
    if (key === '$where') return prop.value;
  }
  return undefined;
}

export function runInterproc(parsed: readonly ParsedSource[]): Finding[] {
  const files = new Set(parsed.map((p) => p.file));
  const byFile = new Map(parsed.map((p) => [p.file, p]));
  const functions = new Map<string, FnInfo>();
  const requires = new Map<string, Map<string, string>>();
  const instances = new Map<string, Map<string, string>>();

  for (const p of parsed) {
    const ns = collectRequires(p.file, p.ast, files);
    requires.set(p.file, ns);
    instances.set(p.file, collectInstances(p.ast, ns));
    for (const fn of collectFunctions(p.file, p.ast)) {
      functions.set(`${fn.file}#${fn.name}`, fn);
    }
  }

  if (taintV2Enabled()) {
    const barrels = new Map<string, Map<string, { spec: string; name: string }>>();
    for (const p of parsed) barrels.set(p.file, reexportsOf(p.ast));
    for (const ns of requires.values()) {
      for (const [local, target] of ns) {
        const hash = target.indexOf('#');
        if (hash < 0) continue;
        const file = target.slice(0, hash);
        const name = target.slice(hash + 1);
        const re = barrels.get(file)?.get(name);
        if (re === undefined) continue;
        const resolved = resolveRelative(file, re.spec, files);
        if (resolved !== undefined) ns.set(local, `${resolved}#${re.name}`);
      }
    }
  }

  const queue: Seed[] = [];
  for (const p of parsed) {
    const facts = analyzeFile(p.ast);
    const ns = requires.get(p.file) ?? new Map<string, string>();
    const inst = instances.get(p.file) ?? new Map<string, string>();
    walk(p.ast, (node) => {
      if (node.type !== 'CallExpression') return;
      const target = resolveCallee(node, ns, inst, p.file, functions);
      if (target === undefined) return;
      node.arguments.forEach((arg, i) => {
        if (arg.type === 'SpreadElement') return;
        if (arg.type === 'CallExpression' && isSchemaValidatorCall(arg)) return;
        if (!nodeIsTainted(arg, facts)) return;
        queue.push({
          file: target.file,
          name: target.name,
          paramIndex: i,
          trace: [
            {
              file: p.file,
              line: node.loc?.start.line,
              note: `tainted argument ${i} passed to ${target.name}()`,
            },
          ],
        });
      });
    });
  }

  const findings: Finding[] = [];
  const seen = new Set<string>();

  while (queue.length > 0) {
    const seed = queue.shift();
    if (seed === undefined) continue;
    if (seed.trace.length > MAX_HOPS) continue;
    const key = `${seed.file}#${seed.name}#${seed.paramIndex}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const fn = functions.get(`${seed.file}#${seed.name}`);
    if (fn === undefined) continue;
    const param = fn.params[seed.paramIndex];
    if (param === undefined) continue;
    const facts = analyzeFunctionWithSeed(fn.node, [param]);
    const p = byFile.get(fn.file);
    if (p === undefined) continue;
    const ns = requires.get(fn.file) ?? new Map<string, string>();
    const inst = instances.get(fn.file) ?? new Map<string, string>();

    walk(fn.node, (node) => {
      if (node.type === 'ObjectExpression') {
        const where = whereValue(node);
        if (where !== undefined && exprIsTainted(where, facts.tainted)) {
          pushSinkFinding({
            findings,
            p,
            fn,
            seed,
            node,
            ruleId: 'SAST-NOSQLI-001',
            title: 'NoSQL injection via $where interpolation',
            cwe: 'CWE-943',
            sinkName: '$where',
          });
        }
      }
      if (node.type !== 'CallExpression') return;
      const first = node.arguments[0];
      const taintedFirst =
        first !== undefined && first.type !== 'SpreadElement' && exprIsTainted(first, facts.tainted);
      if (taintedFirst && (isSqlSink(node) || isCmdSink(node))) {
        const ruleId = isSqlSink(node) ? 'SAST-SQLI-001' : 'SAST-CMDI-001';
        pushSinkFinding({
          findings,
          p,
          fn,
          seed,
          node,
          ruleId,
          title: ruleId === 'SAST-SQLI-001' ? 'SQL injection via string concatenation' : 'Command injection',
          cwe: ruleId === 'SAST-SQLI-001' ? 'CWE-89' : 'CWE-78',
          sinkName: calleeName(node) ?? 'sink',
        });
      }
      const target = resolveCallee(node, ns, inst, fn.file, functions);
      if (target === undefined) return;
      node.arguments.forEach((arg, i) => {
        if (arg.type === 'SpreadElement') return;
        if (arg.type === 'CallExpression' && isSchemaValidatorCall(arg)) return;
        if (!exprIsTainted(arg, facts.tainted)) return;
        queue.push({
          file: target.file,
          name: target.name,
          paramIndex: i,
          trace: [
            ...seed.trace,
            {
              file: fn.file,
              line: node.loc?.start.line,
              note: `${fn.name} forwards tainted ${param} to ${target.name}()`,
            },
          ],
        });
      });
    });
  }

  return findings;
}

function pushSinkFinding(args: {
  findings: Finding[];
  p: ParsedSource;
  fn: FnInfo;
  seed: Seed;
  node: AstNode;
  ruleId: string;
  title: string;
  cwe: string;
  sinkName: string;
}): void {
  const snippet = args.p.source
    .slice(args.node.range?.[0] ?? 0, args.node.range?.[1] ?? 0)
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 120);
  const trace = [
    ...args.seed.trace,
    {
      file: args.fn.file,
      line: args.node.loc?.start.line,
      note: `tainted value reaches ${args.sinkName}`,
    },
  ];
  args.findings.push({
    id: makeFindingId(args.ruleId, args.fn.file, `${args.node.loc?.start.line ?? 0}|${snippet}`),
    ruleId: args.ruleId,
    module: 'sast',
    title: args.title,
    severity: 'high',
    confidence: 'high',
    cwe: args.cwe,
    file: args.fn.file,
    line: args.node.loc?.start.line,
    snippet,
    message: `Tainted input crosses ${new Set(trace.map((t) => t.file)).size} files and reaches ${args.sinkName}.`,
    remediation: 'Pass the value through a parameterized API or a recognized sanitizer before the sink.',
    references: [args.ruleId],
    trace,
  });
}
