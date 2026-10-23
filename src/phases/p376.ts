/**
 * Phase 376. Symbol-level unused dependencies.
 * Off unless FULLSHIELD_EXPERIMENTAL_DEADSYM=1.
 * Does not edit the manifest and does not propose a deletion.
 */
import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_DEADSYM';
export const TYPEONLY_FLAG = 'FULLSHIELD_EXPERIMENTAL_NPM_REACH_TYPEONLY';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface UnusedSymbolFinding {
  ruleId: 'DEPS-UNUSED-SYMBOLS-001';
  severity: 'info';
  packageName: string;
  names: string[];
  message: string;
}

interface Binding {
  local: string;
  imported: string;
  typeOnly: boolean;
}

function isNode(value: unknown): value is TSESTree.Node {
  if (typeof value !== 'object' || value === null || !('type' in value)) {return false;}
  return typeof value.type === 'string';
}

function walk(node: TSESTree.Node, visit: (node: TSESTree.Node) => void, skipImportBody = false): void {
  if (skipImportBody && node.type === 'ImportDeclaration') {
    visit(node);
    return;
  }
  visit(node);
  const record = node as unknown as Record<string, unknown>;
  for (const value of Object.values(record)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isNode(item)) {
          walk(item, visit, skipImportBody);
        }
      }
    } else if (isNode(value)) {
      walk(value, visit, skipImportBody);
    }
  }
}

function importedName(specifier: TSESTree.ImportSpecifier): string {
  if (specifier.imported.type === 'Identifier') {
    return specifier.imported.name;
  }
  return specifier.local.name;
}

function pushBinding(list: Binding[], specifier: TSESTree.ImportDeclaration['specifiers'][number], typeDecl: boolean): void {
  if (specifier.type === 'ImportSpecifier') {
    list.push({ local: specifier.local.name, imported: importedName(specifier), typeOnly: typeDecl || specifier.importKind === 'type' });
    return;
  }
  list.push({ local: specifier.local.name, imported: specifier.local.name, typeOnly: typeDecl });
}

function ignoredSpecifier(spec: string, direct: readonly string[]): boolean {
  if (!direct.includes(spec) || spec.startsWith('.') || spec.startsWith('node:')) {
    return true;
  }
  return false;
}

function recordImport(node: TSESTree.Node, direct: readonly string[], bindings: Map<string, Binding[]>): void {
  if (node.type !== 'ImportDeclaration') {
    return;
  }
  const spec = typeof node.source.value === 'string' ? node.source.value : '';
  if (ignoredSpecifier(spec, direct) || node.specifiers.length === 0) {
    return;
  }
  const typeDecl = node.importKind === 'type';
  const list = bindings.get(spec) ?? [];
  for (const specifier of node.specifiers) {
    pushBinding(list, specifier, typeDecl);
  }
  bindings.set(spec, list);
}

function recordDynamic(node: TSESTree.Node, dynamic: Set<string>): void {
  if (node.type === 'ImportExpression' && node.source.type === 'Literal' && typeof node.source.value === 'string') {
    dynamic.add(node.source.value);
  }
}

function collectBindings(ast: TSESTree.Program, direct: readonly string[]): { bindings: Map<string, Binding[]>; dynamic: Set<string> } {
  const bindings = new Map<string, Binding[]>();
  const dynamic = new Set<string>();
  walk(ast, (node) => {
    recordImport(node, direct, bindings);
    recordDynamic(node, dynamic);
  });
  return { bindings, dynamic };
}

function identifierUses(ast: TSESTree.Program): Set<string> {
  const uses = new Set<string>();
  walk(ast, (node) => {
    if (node.type === 'Identifier') {
      uses.add(node.name);
    }
  }, true);
  return uses;
}

function symbolFinding(packageName: string, names: string[], message: string): UnusedSymbolFinding {
  return { ruleId: 'DEPS-UNUSED-SYMBOLS-001', severity: 'info', packageName, names, message };
}

function findingFor(packageName: string, specs: readonly Binding[], uses: ReadonlySet<string>, typeOnlyCountsAsUse: boolean): UnusedSymbolFinding | undefined {
  if (typeOnlyCountsAsUse && specs.some((spec) => spec.typeOnly)) {
    return undefined;
  }
  const runtime = specs.filter((spec) => !spec.typeOnly);
  if (runtime.length === 0) {
    const names = specs.map((spec) => spec.imported);
    return symbolFinding(packageName, names, `${packageName} is not runtime-used (${names.join(', ')}). Type-only imports do not count as use.`);
  }
  const unused = runtime.filter((spec) => !uses.has(spec.local));
  if (unused.length !== runtime.length) {
    return undefined;
  }
  const names = unused.map((spec) => spec.imported);
  return symbolFinding(packageName, names, `Unused imported names from ${packageName}: ${names.join(', ')}`);
}

export function unusedSymbols(source: string, direct: readonly string[]): UnusedSymbolFinding[] {
  if (!enabled()) {
    return [];
  }
  let ast: TSESTree.Program;
  try {
    ast = parse(source, { loc: false, range: false, jsx: true });
  } catch {
    return [];
  }
  const typeOnlyCountsAsUse = process.env[TYPEONLY_FLAG] !== '1';
  const { bindings, dynamic } = collectBindings(ast, direct);
  const uses = identifierUses(ast);
  const findings: UnusedSymbolFinding[] = [];
  for (const [packageName, specs] of bindings) {
    if (dynamic.has(packageName)) {
      continue;
    }
    const hit = findingFor(packageName, specs, uses, typeOnlyCountsAsUse);
    if (hit !== undefined) {
      findings.push(hit);
    }
  }
  return findings;
}
