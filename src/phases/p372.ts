/**
 * Phase 372. Copied vulnerable snippets.
 * Off unless FULLSHIELD_EXPERIMENTAL_SNIPPET=1.
 * Hashes a normalized AST. Does not download the body file.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_SNIPPET';
export const MIN_NODES = 40;

/** Listed so the phase test can pin them. */
export const NORMALIZATION_RULES = [
  'Identifier names become id',
  'Literal values become lit',
  'Template quasis become lit',
  'Node type and child order are preserved',
] as const;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface ReviewedBody {
  osvId: string;
  reviewed: boolean;
  /** Local path. The scanner does not fetch it. */
  bodyPath: string;
}

export interface SnippetFile {
  path: string;
  source: string;
}

export interface SnippetFinding {
  ruleId: 'SAST-COPIED-SNIPPET-001';
  severity: 'info';
  file: string;
  osvId: string;
  message: string;
}

export interface SnippetIndex {
  hash: string;
  osvId: string;
  nodes: number;
}

function isNode(value: unknown): value is TSESTree.Node {
  if (typeof value !== 'object' || value === null || !('type' in value)) {return false;}
  return typeof value.type === 'string';
}

function normalize(node: TSESTree.Node): unknown {
  const record = node as unknown as Record<string, unknown>;
  const out: Record<string, unknown> = { type: node.type };
  if (node.type === 'Identifier') {
    out.name = 'id';
  }
  if (node.type === 'Literal') {
    out.value = 'lit';
  }
  if (node.type === 'TemplateElement') {
    out.value = 'lit';
  }
  for (const [key, value] of Object.entries(record)) {
    if (key === 'type' || key === 'loc' || key === 'range' || key === 'start' || key === 'end' || key === 'parent') {
      continue;
    }
    if (node.type === 'Identifier' && key === 'name') {
      continue;
    }
    if (node.type === 'Literal' && (key === 'value' || key === 'raw')) {
      continue;
    }
    if (node.type === 'TemplateElement' && (key === 'value' || key === 'tail')) {
      continue;
    }
    if (Array.isArray(value)) {
      const nodes = value.filter(isNode);
      if (nodes.length > 0) {
        out[key] = nodes.map((child) => normalize(child));
      }
    } else if (isNode(value)) {
      out[key] = normalize(value);
    }
  }
  return out;
}

export function countNodes(node: TSESTree.Node): number {
  let count = 1;
  const record = node as unknown as Record<string, unknown>;
  for (const value of Object.values(record)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isNode(item)) {
          count += countNodes(item);
        }
      }
    } else if (isNode(value)) {
      count += countNodes(value);
    }
  }
  return count;
}

function functionsIn(source: string): Array<{ nodes: number; hash: string }> {
  let ast: TSESTree.Program;
  try {
    ast = parse(source, { loc: false, range: false, jsx: false });
  } catch {
    return [];
  }
  const found: Array<{ nodes: number; hash: string }> = [];
  const visit = (node: TSESTree.Node): void => {
    if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
      const nodes = countNodes(node);
      if (nodes >= MIN_NODES) {
        const hash = createHash('sha256').update(JSON.stringify(normalize(node))).digest('hex');
        found.push({ nodes, hash });
      }
    }
    const record = node as unknown as Record<string, unknown>;
    for (const value of Object.values(record)) {
      if (Array.isArray(value)) {
        for (const item of value) {
          if (isNode(item)) {
            visit(item);
          }
        }
      } else if (isNode(value)) {
        visit(value);
      }
    }
  };
  visit(ast);
  return found;
}

export function indexReviewed(
  rows: readonly ReviewedBody[],
  read: (path: string) => string = (filePath: string): string => readFileSync(filePath, 'utf8'),
): SnippetIndex[] {
  if (!enabled()) {
    return [];
  }
  const index: SnippetIndex[] = [];
  for (const row of rows) {
    if (!row.reviewed) {
      continue;
    }
    const source = read(row.bodyPath);
    for (const fn of functionsIn(source)) {
      index.push({ hash: fn.hash, osvId: row.osvId, nodes: fn.nodes });
    }
  }
  return index;
}

function isSkipped(filePath: string, vendored: readonly string[]): boolean {
  const normalized = filePath.replaceAll('\\', '/');
  if (!normalized.includes('node_modules/')) {
    return false;
  }
  return !vendored.some((prefix) => normalized.includes(prefix.replaceAll('\\', '/')));
}

export function copiedSnippets(
  index: readonly SnippetIndex[],
  files: readonly SnippetFile[],
  vendored: readonly string[] = [],
): SnippetFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: SnippetFinding[] = [];
  for (const file of files) {
    if (isSkipped(file.path, vendored)) {
      continue;
    }
    for (const fn of functionsIn(file.source)) {
      const hit = index.find((row) => row.hash === fn.hash);
      if (hit === undefined) {
        continue;
      }
      findings.push({
        ruleId: 'SAST-COPIED-SNIPPET-001',
        severity: 'info',
        file: file.path,
        osvId: hit.osvId,
        message: `AST matched a reviewed advisory body ${hit.osvId}.`,
      });
    }
  }
  return findings;
}

/** Exposed so the test can show a 10-node function never enters the index. */
export function indexedNodeCounts(source: string): number[] {
  return functionsIn(source).map((fn) => fn.nodes);
}
