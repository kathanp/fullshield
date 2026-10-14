import type { TSESTree } from '@typescript-eslint/typescript-estree';

import type { Severity } from '../../core/finding.js';

export type AstNode = TSESTree.Node;

export interface SastRuleMeta {
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  docs: string;
}

export interface SastReport {
  node: AstNode;
  message: string;
}

export interface RuleContext {
  filename: string;
  source: string;
  report(report: SastReport): void;
  isTainted(node: AstNode): boolean;
  isPathSanitized(node: AstNode): boolean;
  isSanitizedFor(node: AstNode, kind: 'url' | 'xss'): boolean;
  isRequestObject(node: AstNode): boolean;
  functionHasPasswordName(node: AstNode): boolean;
  assignedName(node: AstNode): string | undefined;
}

export type Visitor = (node: AstNode) => void;

export interface SastRule {
  meta: SastRuleMeta;
  create(ctx: RuleContext): Partial<Record<string, Visitor>>;
}
