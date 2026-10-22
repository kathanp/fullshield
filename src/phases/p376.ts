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
  const bindings = new Map<string, Binding[]>();
  const dynamic = new Set<string>();
  walk(ast, (node) => {
    if (node.type === 'ImportDeclaration') {
      const spec = typeof node.source.value === 'string' ? node.source.value : '';
      if (!direct.includes(spec) || spec.startsWith('.') || spec.startsWith('node:')) {
        return;
      }
      if (node.specifiers.length === 0) {
        return;
      }
      const typeDecl = node.importKind === 'type';
      const list = bindings.get(spec) ?? [];
      for (const specifier of node.specifiers) {
        if (specifier.type === 'ImportSpecifier') {
          const imported = specifier.imported.type === 'Identifier' ? specifier.imported.name : specifier.local.name;
          list.push({
            local: specifier.local.name,
            imported,
            typeOnly: typeDecl || specifier.importKind === 'type',
          });
        } else {
          list.push({
            local: specifier.local.name,
            imported: specifier.local.name,
            typeOnly: typeDecl,
          });
        }
      }
      bindings.set(spec, list);
    }
    if (node.type === 'ImportExpression' && node.source.type === 'Literal' && typeof node.source.value === 'string') {
      dynamic.add(node.source.value);
    }
  });
  const uses = new Set<string>();
  walk(ast, (node) => {
    if (node.type === 'Identifier') {
      uses.add(node.name);
    }
  }, true);
  const findings: UnusedSymbolFinding[] = [];
  for (const [packageName, specs] of bindings) {
    if (dynamic.has(packageName)) {
      continue;
    }
    if (typeOnlyCountsAsUse && specs.some((spec) => spec.typeOnly)) {
      continue;
    }
    const runtime = specs.filter((spec) => !spec.typeOnly);
    if (runtime.length === 0) {
      const names = specs.map((spec) => spec.imported);
      findings.push({
        ruleId: 'DEPS-UNUSED-SYMBOLS-001',
        severity: 'info',
        packageName,
        names,
        message: `${packageName} is not runtime-used (${names.join(', ')}). Type-only imports do not count as use.`,
      });
      continue;
    }
    const unused = runtime.filter((spec) => !uses.has(spec.local));
    if (unused.length !== runtime.length) {
      continue;
    }
    const names = unused.map((spec) => spec.imported);
    findings.push({
      ruleId: 'DEPS-UNUSED-SYMBOLS-001',
      severity: 'info',
      packageName,
      names,
      message: `Unused imported names from ${packageName}: ${names.join(', ')}`,
    });
  }
  return findings;
}
