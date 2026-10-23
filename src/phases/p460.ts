/**
 * Phase 460. Production source-map flags.
 * Off unless FULLSHIELD_EXPERIMENTAL_PRODMAP=1.
 * Flag off: the baseline finding list is returned unchanged.
 * Config is parsed as an AST and is not executed.
 */
import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PRODMAP';
export const SOURCEMAP_RULE = 'CONFIG-SOURCEMAP-001';

const FULL_MAPS = new Set([
  'source-map',
  'inline-source-map',
  'hidden-source-map',
  'nosources-source-map',
  'eval-source-map',
  'cheap-module-source-map',
  'cheap-source-map',
]);

const SERVER_ONLY = new Set(['serverSourceMaps', 'productionServerSourceMaps']);

function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PhaseFinding {
  ruleId: typeof SOURCEMAP_RULE;
  severity: 'low';
  file: string;
  line: number;
  message: string;
}

function isDevOnly(test: TSESTree.Node | null | undefined): boolean {
  if (test === undefined || test === null || test.type !== 'BinaryExpression' || test.operator !== '!==') {
    return false;
  }
  const left = test.left;
  const right = test.right;
  if (left.type !== 'MemberExpression' || right.type !== 'Literal' || right.value !== 'production') {
    return false;
  }
  const env = left.object;
  return left.property.type === 'Identifier' && left.property.name === 'NODE_ENV' && env.type === 'MemberExpression';
}

function propertyName(node: TSESTree.Node): string | null {
  if (node.type === 'Identifier') {
    return node.name;
  }
  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }
  return null;
}

function literal(node: TSESTree.Node): string | boolean | null {
  if (node.type === 'Literal' && (typeof node.value === 'string' || typeof node.value === 'boolean')) {
    return node.value;
  }
  return null;
}

function visit(node: TSESTree.Node, file: string, devOnly: boolean, findings: PhaseFinding[]): void {
  if (node.type === 'IfStatement' && isDevOnly(node.test)) {
    visit(node.consequent, file, true, findings);
    if (node.alternate !== null) {
      visit(node.alternate, file, devOnly, findings);
    }
    return;
  }
  if (node.type === 'Property' && !devOnly) {
    const name = propertyName(node.key);
    const value = literal(node.value);
    if (name !== null && !SERVER_ONLY.has(name)) {
      const browser = name === 'productionBrowserSourceMaps' && value === true;
      const fullMap = name === 'devtool' && typeof value === 'string' && FULL_MAPS.has(value);
      if (browser || fullMap) {
        findings.push({
          ruleId: SOURCEMAP_RULE,
          severity: 'low',
          file,
          line: node.loc?.start.line ?? 1,
          message: 'the flag is set',
        });
      }
    }
  }
  for (const key of Object.keys(node)) {
    if (key === 'parent' || (node.type === 'IfStatement' && (key === 'consequent' || key === 'alternate'))) {
      continue;
    }
    const child = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (typeof item === 'object' && item !== null && 'type' in item) {
          visit(item as TSESTree.Node, file, devOnly, findings);
        }
      }
    } else if (typeof child === 'object' && child !== null && 'type' in child) {
      visit(child as TSESTree.Node, file, devOnly, findings);
    }
  }
}

export function scanSourceMapConfig(file: string, text: string, baseline: readonly PhaseFinding[] = []): PhaseFinding[] {
  if (!enabled()) {
    return [...baseline];
  }
  let ast: TSESTree.Program;
  try {
    ast = parse(text, { loc: true, range: false, jsx: false });
  } catch {
    return [...baseline];
  }
  const findings: PhaseFinding[] = [];
  visit(ast, file, false, findings);
  return [...baseline, ...findings];
}
