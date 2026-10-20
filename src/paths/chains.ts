import type { Finding } from '../core/finding.js';
import { packageNameFromSpec } from '../modules/deps/evidence.js';
import { calleeName, literalString, propName, walk } from '../modules/sast/ast.js';
import { collectRequires } from '../modules/sast/interproc.js';
import type { AstNode } from '../modules/sast/types.js';
import { entryOf, routeAt, type RouteInfo } from './routes.js';
import { sinkOf, type AttackPath, type AttackPathStep } from './types.js';

const SINK_RULES = new Set([
  'SAST-SQLI-001',
  'SAST-NOSQLI-001',
  'SAST-CMDI-001',
  'SAST-PATH-001',
  'SAST-XSS-001',
  'SAST-SSRF-001',
  'SAST-REDIRECT-001',
  'SAST-EVAL-001',
  'SAST-PROTO-001',
  'SAST-JWT-001',
]);

const REACHABLE = new Set<NonNullable<Finding['reachability']>>(['reachable', 'symbol-reachable']);

interface CallSite {
  file: string;
  line: number;
  symbol: string;
}

interface Consumer {
  file: string;
  line: number;
  note: string;
}

export function sinkPaths(findings: readonly Finding[], routes: readonly RouteInfo[]): AttackPath[] {
  const out: AttackPath[] = [];
  for (const finding of findings) {
    if (!SINK_RULES.has(finding.ruleId)) continue;
    const route = routeForFinding(finding, routes);
    if (route === undefined) continue;
    out.push({
      kind: 'sink',
      entry: entryOf(route),
      steps: finding.trace ?? [],
      sink: sinkOf(finding),
      findingIds: [finding.id],
    });
  }
  return out;
}

function routeForFinding(finding: Finding, routes: readonly RouteInfo[]): RouteInfo | undefined {
  if (finding.file !== undefined && finding.line !== undefined) {
    const direct = routeAt(routes, finding.file, finding.line);
    if (direct !== undefined) return direct;
  }
  for (const step of finding.trace ?? []) {
    if (step.line === undefined) continue;
    const hit = routeAt(routes, step.file, step.line);
    if (hit !== undefined) return hit;
  }
  return undefined;
}

export function dependencyPaths(
  findings: readonly Finding[],
  routes: readonly RouteInfo[],
  asts: ReadonlyMap<string, AstNode>,
): AttackPath[] {
  const out: AttackPath[] = [];
  for (const finding of findings) {
    if (!isReachableDep(finding)) continue;
    out.push(...pathsForDep(finding, callSites(finding, asts), routes));
  }
  return out;
}

function isReachableDep(finding: Finding): boolean {
  return finding.module === 'deps' && finding.reachability !== undefined && REACHABLE.has(finding.reachability);
}

function pathsForDep(finding: Finding, sites: readonly CallSite[], routes: readonly RouteInfo[]): AttackPath[] {
  const grouped = new Map<string, { route: RouteInfo; steps: AttackPathStep[] }>();
  for (const site of sites) {
    const route = routeAt(routes, site.file, site.line);
    if (route === undefined) continue;
    const key = `${route.file}|${route.method}|${route.path}|${finding.id}`;
    const group = grouped.get(key) ?? { route, steps: [] };
    group.steps.push({ file: site.file, line: site.line, note: `call ${site.symbol}` });
    grouped.set(key, group);
  }
  return [...grouped.values()].map((group) => ({
    kind: 'dependency' as const,
    entry: entryOf(group.route),
    steps: group.steps,
    sink: sinkOf(finding),
    findingIds: [finding.id],
  }));
}

function callSites(finding: Finding, asts: ReadonlyMap<string, AstNode>): CallSite[] {
  const listed = finding.reachabilityEvidence?.calls;
  if (listed !== undefined) {
    return listed.map((call) => ({ file: call.file, line: call.line, symbol: call.symbol }));
  }
  const pkg = packageFromSnippet(finding.snippet);
  if (pkg === undefined) return [];
  return discoverCalls(pkg, asts);
}

function packageFromSnippet(snippet: string | undefined): string | undefined {
  if (snippet === undefined || snippet.length === 0) return undefined;
  const at = snippet.startsWith('@') ? snippet.indexOf('@', 1) : snippet.indexOf('@');
  const pkg = at <= 0 ? snippet : snippet.slice(0, at);
  return pkg.length > 0 ? pkg : undefined;
}

function discoverCalls(pkg: string, asts: ReadonlyMap<string, AstNode>): CallSite[] {
  const sites: CallSite[] = [];
  for (const [file, ast] of asts) sites.push(...callsInFile(file, ast, pkg));
  return sites;
}

function callsInFile(file: string, ast: AstNode, pkg: string): CallSite[] {
  const locals = localsForPackage(ast, pkg);
  const sites: CallSite[] = [];
  walk(ast, (node) => {
    const site = callSite(node, file, locals);
    if (site !== undefined) sites.push(site);
  });
  return sites;
}

function callSite(node: AstNode, file: string, locals: ReadonlySet<string>): CallSite | undefined {
  if (node.type !== 'CallExpression') return undefined;
  const line = node.loc?.start.line;
  if (line === undefined) return undefined;
  if (node.callee.type === 'Identifier' && locals.has(node.callee.name)) {
    return { file, line, symbol: node.callee.name };
  }
  if (node.callee.type !== 'MemberExpression' || node.callee.object.type !== 'Identifier') return undefined;
  if (!locals.has(node.callee.object.name)) return undefined;
  return { file, line, symbol: propName(node.callee) ?? node.callee.object.name };
}

function localsForPackage(ast: AstNode, pkg: string): Set<string> {
  const names = new Set<string>();
  walk(ast, (node) => {
    for (const name of bindingNames(node, pkg)) names.add(name);
  });
  return names;
}

function bindingNames(node: AstNode, pkg: string): string[] {
  if (node.type === 'ImportDeclaration') return importNames(node, pkg);
  if (node.type !== 'VariableDeclarator' || node.init === null) return [];
  const spec = requireSpec(node.init);
  if (spec === undefined || packageNameFromSpec(spec) !== pkg) return [];
  if (node.id.type === 'Identifier') return [node.id.name];
  if (node.id.type !== 'ObjectPattern') return [];
  return node.id.properties.flatMap((prop) => {
    if (prop.type !== 'Property' || prop.value.type !== 'Identifier') return [];
    return [prop.value.name];
  });
}

function importNames(node: AstNode, pkg: string): string[] {
  if (node.type !== 'ImportDeclaration') return [];
  const spec = literalString(node.source);
  if (spec === undefined || packageNameFromSpec(spec) !== pkg) return [];
  return node.specifiers.flatMap((specifier) => {
    if (specifier.type === 'ImportDefaultSpecifier' || specifier.type === 'ImportNamespaceSpecifier') {
      return [specifier.local.name];
    }
    return [];
  });
}

function requireSpec(node: AstNode): string | undefined {
  if (node.type !== 'CallExpression' || node.callee.type !== 'Identifier' || node.callee.name !== 'require') {
    return undefined;
  }
  const arg = node.arguments[0];
  if (arg === undefined || arg.type === 'SpreadElement') return undefined;
  return literalString(arg);
}

export function secretPaths(
  findings: readonly Finding[],
  routes: readonly RouteInfo[],
  asts: ReadonlyMap<string, AstNode>,
): AttackPath[] {
  const out: AttackPath[] = [];
  for (const finding of findings) {
    if (finding.module !== 'secrets' || finding.file === undefined || finding.line === undefined) continue;
    const ast = asts.get(finding.file);
    if (ast === undefined) continue;
    const name = bindingAt(ast, finding.line);
    if (name === undefined) continue;
    out.push(...pathsForSecret(finding, secretConsumers(finding.file, name, asts), findings, routes));
  }
  return out;
}

function pathsForSecret(
  finding: Finding,
  consumers: readonly Consumer[],
  findings: readonly Finding[],
  routes: readonly RouteInfo[],
): AttackPath[] {
  return consumers.map((consumer) => {
    const route = routeAt(routes, consumer.file, consumer.line);
    const extra = findings.filter((row) => row.id !== finding.id && row.file === consumer.file && row.line === consumer.line);
    const known = new Set(findings.map((row) => row.id));
    return {
      kind: 'secret' as const,
      ...(route !== undefined ? { entry: entryOf(route) } : {}),
      steps: [{ file: consumer.file, line: consumer.line, note: consumer.note }],
      sink: sinkOf(finding),
      findingIds: [finding.id, ...extra.map((row) => row.id)].filter((id) => known.has(id)),
    };
  });
}

function bindingAt(ast: AstNode, line: number): string | undefined {
  let found: string | undefined;
  walk(ast, (node) => {
    if (found !== undefined) return;
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.loc?.start.line === line) {
      found = node.id.name;
    }
  });
  return found;
}

function secretConsumers(startFile: string, startName: string, asts: ReadonlyMap<string, AstNode>): Consumer[] {
  const files = new Set(asts.keys());
  const requires = requireMaps(asts, files);
  const out: Consumer[] = [];
  const seen = new Set<string>();
  const queue: Array<{ file: string; name: string; depth: number }> = [{ file: startFile, name: startName, depth: 0 }];
  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined || current.depth > 5 || seen.has(`${current.file}#${current.name}`)) continue;
    seen.add(`${current.file}#${current.name}`);
    collectAliasUses(current, asts, requires, out, queue);
  }
  return dedupeConsumers(out);
}

function requireMaps(
  asts: ReadonlyMap<string, AstNode>,
  files: ReadonlySet<string>,
): Map<string, Map<string, string>> {
  const maps = new Map<string, Map<string, string>>();
  for (const [file, ast] of asts) maps.set(file, collectRequires(file, ast, files));
  return maps;
}

function collectAliasUses(
  current: { file: string; name: string; depth: number },
  asts: ReadonlyMap<string, AstNode>,
  requires: ReadonlyMap<string, Map<string, string>>,
  out: Consumer[],
  queue: Array<{ file: string; name: string; depth: number }>,
): void {
  const ast = asts.get(current.file);
  if (ast !== undefined) out.push(...consumersOf(current.file, current.name, ast));
  for (const [other, map] of requires) followImport(current, other, map, asts, out, queue);
}

function followImport(
  current: { file: string; name: string; depth: number },
  other: string,
  map: ReadonlyMap<string, string>,
  asts: ReadonlyMap<string, AstNode>,
  out: Consumer[],
  queue: Array<{ file: string; name: string; depth: number }>,
): void {
  for (const [local, target] of map) {
    if (target === `${current.file}#${current.name}`) {
      queue.push({ file: other, name: local, depth: current.depth + 1 });
    }
    if (target !== current.file) continue;
    const otherAst = asts.get(other);
    if (otherAst !== undefined) out.push(...memberConsumers(other, otherAst, local, current.name));
  }
}

function consumersOf(file: string, name: string, ast: AstNode): Consumer[] {
  const out: Consumer[] = [];
  walk(ast, (node) => {
    if (node.type !== 'Identifier' || node.name !== name) return;
    const call = enclosingCall(node);
    if (call === undefined) return;
    out.push({ file, line: node.loc?.start.line ?? call.loc?.start.line ?? 1, note: `${name} passed to ${calleeName(call) ?? 'call'}` });
  });
  return out;
}

function memberConsumers(file: string, ast: AstNode, objectName: string, prop: string): Consumer[] {
  const out: Consumer[] = [];
  walk(ast, (node) => {
    if (node.type !== 'MemberExpression' || propName(node) !== prop) return;
    if (node.object.type !== 'Identifier' || node.object.name !== objectName) return;
    const call = enclosingCall(node);
    if (call === undefined) return;
    out.push({
      file,
      line: node.loc?.start.line ?? 1,
      note: `${prop} passed to ${calleeName(call) ?? 'call'}`,
    });
  });
  return out;
}

function enclosingCall(node: AstNode): AstNode | undefined {
  let current = parentOf(node);
  while (current !== undefined) {
    if ((current.type === 'CallExpression' || current.type === 'NewExpression') && !insideCallee(node, current)) {
      return current;
    }
    current = parentOf(current);
  }
  return undefined;
}

function insideCallee(node: AstNode, call: AstNode): boolean {
  if (call.type !== 'CallExpression' && call.type !== 'NewExpression') return false;
  let current: AstNode | undefined = node;
  while (current !== undefined && current !== call) {
    if (current === call.callee) return true;
    current = parentOf(current);
  }
  return false;
}

function parentOf(node: AstNode): AstNode | undefined {
  return (node as unknown as { parent?: AstNode }).parent;
}

function dedupeConsumers(consumers: readonly Consumer[]): Consumer[] {
  const seen = new Set<string>();
  const out: Consumer[] = [];
  for (const consumer of consumers) {
    const key = `${consumer.file}:${consumer.line ?? ''}:${consumer.note}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(consumer);
  }
  return out;
}
