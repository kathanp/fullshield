import { enclosingScope, walk } from '../ast.js';
import { nodeIsTainted, type ScopeFacts } from '../taint.js';
import type { AstNode } from '../types.js';
import type { CompiledSemgrepRule } from './compile.js';

const ELLIPSIS = '__fs_ellipsis';
const META = /^__fs_m_([A-Za-z_][A-Za-z0-9_]*)$/;

type Bindings = Map<string, AstNode>;

function unwrap(node: AstNode): AstNode {
  if (node.type === 'ChainExpression') {return unwrap(node.expression);}
  return node;
}

function isEllipsis(node: AstNode): boolean {
  return node.type === 'Identifier' && node.name === ELLIPSIS;
}

function metaName(node: AstNode): string | undefined {
  if (node.type !== 'Identifier') {return undefined;}
  return META.exec(node.name)?.[1];
}

function commit(target: Bindings, source: Bindings): void {
  target.clear();
  for (const [key, value] of source) {target.set(key, value);}
}

function sameShape(left: AstNode, right: AstNode): boolean {
  const a = unwrap(left);
  const b = unwrap(right);
  if (a.type !== b.type) {return false;}
  if (a.type === 'Identifier' && b.type === 'Identifier') {return a.name === b.name;}
  if (a.type === 'Literal' && b.type === 'Literal') {return a.value === b.value;}
  if (a.type === 'MemberExpression' && b.type === 'MemberExpression') {
    return a.computed === b.computed && sameShape(a.object, b.object) && sameShape(a.property, b.property);
  }
  if (a.type === 'CallExpression' && b.type === 'CallExpression') {
    return sameShape(a.callee, b.callee) && sameList(a.arguments, b.arguments);
  }
  if (a.type === 'NewExpression' && b.type === 'NewExpression') {
    return sameShape(a.callee, b.callee) && sameList(a.arguments, b.arguments);
  }
  if (a.type === 'TemplateLiteral' && b.type === 'TemplateLiteral') {
    return (
      a.expressions.length === 0 &&
      b.expressions.length === 0 &&
      a.quasis[0]?.value.cooked === b.quasis[0]?.value.cooked
    );
  }
  return false;
}

function sameList(left: readonly (AstNode | null)[], right: readonly (AstNode | null)[]): boolean {
  if (left.length !== right.length) {return false;}
  for (let i = 0; i < left.length; i += 1) {
    const a = left[i];
    const b = right[i];
    if (a === null || a === undefined || b === null || b === undefined) {return false;}
    if (a.type === 'SpreadElement' || b.type === 'SpreadElement') {return false;}
    if (!sameShape(a, b)) {return false;}
  }
  return true;
}

function matchRaw(pattern: AstNode, node: AstNode, bindings: Bindings): boolean {
  const current = unwrap(node);
  const meta = metaName(pattern);
  if (meta !== undefined) {
    const prev = bindings.get(meta);
    if (prev === undefined) {
      bindings.set(meta, current);
      return true;
    }
    return sameShape(prev, current);
  }
  if (isEllipsis(pattern)) {return false;}
  if (pattern.type === 'Literal' && current.type === 'TemplateLiteral' && typeof pattern.value === 'string') {
    return current.expressions.length === 0 && current.quasis[0]?.value.cooked === pattern.value;
  }
  if (pattern.type === 'TemplateLiteral' && current.type === 'Literal' && pattern.expressions.length === 0) {
    return current.value === pattern.quasis[0]?.value.cooked;
  }
  if (pattern.type !== current.type) {return false;}
  if (pattern.type === 'Identifier' && current.type === 'Identifier') {return pattern.name === current.name;}
  if (pattern.type === 'Literal' && current.type === 'Literal') {return pattern.value === current.value;}
  if (pattern.type === 'TemplateLiteral' && current.type === 'TemplateLiteral') {
    return (
      pattern.expressions.length === 0 &&
      current.expressions.length === 0 &&
      pattern.quasis[0]?.value.cooked === current.quasis[0]?.value.cooked
    );
  }
  if (pattern.type === 'MemberExpression' && current.type === 'MemberExpression') {
    return (
      pattern.computed === current.computed &&
      matchRaw(pattern.object, current.object, bindings) &&
      matchRaw(pattern.property, current.property, bindings)
    );
  }
  if (pattern.type === 'CallExpression' && current.type === 'CallExpression') {
    if ((pattern.optional === true) !== (current.optional === true)) {return false;}
    return matchRaw(pattern.callee, current.callee, bindings) && matchArgs(pattern.arguments, current.arguments, bindings);
  }
  if (pattern.type === 'NewExpression' && current.type === 'NewExpression') {
    return matchRaw(pattern.callee, current.callee, bindings) && matchArgs(pattern.arguments, current.arguments, bindings);
  }
  if (pattern.type === 'ExpressionStatement' && current.type === 'ExpressionStatement') {
    return matchRaw(pattern.expression, current.expression, bindings);
  }
  if (pattern.type === 'BlockStatement' && current.type === 'BlockStatement') {
    return matchStatementList(pattern.body, current.body, bindings);
  }
  if (pattern.type === 'FunctionDeclaration' && current.type === 'FunctionDeclaration') {
    if (pattern.async !== current.async || pattern.generator !== current.generator) {return false;}
    if (!matchOptional(pattern.id ?? undefined, current.id ?? undefined, bindings)) {return false;}
    return matchStatementList(pattern.params, current.params, bindings) && matchRaw(pattern.body, current.body, bindings);
  }
  return false;
}

function matchOptional(pattern: AstNode | undefined, node: AstNode | undefined, bindings: Bindings): boolean {
  if (pattern === undefined || node === undefined) {return pattern === undefined && node === undefined;}
  return matchRaw(pattern, node, bindings);
}

function matchStatementList(patterns: readonly AstNode[], nodes: readonly AstNode[], bindings: Bindings): boolean {
  if (patterns.length !== nodes.length) {return false;}
  const copy: Bindings = new Map(bindings);
  for (let i = 0; i < patterns.length; i += 1) {
    const pattern = patterns[i];
    const node = nodes[i];
    if (pattern === undefined || node === undefined || !matchRaw(pattern, node, copy)) {return false;}
  }
  commit(bindings, copy);
  return true;
}

function matchArgs(
  patterns: readonly (AstNode | null)[],
  nodes: readonly (AstNode | null)[],
  bindings: Bindings,
): boolean {
  const copy: Bindings = new Map(bindings);
  if (!matchArgAt(patterns, 0, nodes, 0, copy)) {return false;}
  commit(bindings, copy);
  return true;
}

function matchArgAt(
  patterns: readonly (AstNode | null)[],
  patternIndex: number,
  nodes: readonly (AstNode | null)[],
  nodeIndex: number,
  bindings: Bindings,
): boolean {
  if (patternIndex === patterns.length) {return nodeIndex === nodes.length;}
  const pattern = patterns[patternIndex];
  if (pattern === null || pattern === undefined) {return false;}
  if (isEllipsis(pattern)) {
    for (let take = 0; nodeIndex + take <= nodes.length; take += 1) {
      const copy: Bindings = new Map(bindings);
      if (matchArgAt(patterns, patternIndex + 1, nodes, nodeIndex + take, copy)) {
        commit(bindings, copy);
        return true;
      }
    }
    return false;
  }
  const actual = nodes[nodeIndex];
  if (actual === null || actual === undefined || actual.type === 'SpreadElement') {return false;}
  const copy: Bindings = new Map(bindings);
  if (!matchRaw(pattern, actual, copy)) {return false;}
  if (!matchArgAt(patterns, patternIndex + 1, nodes, nodeIndex + 1, copy)) {return false;}
  commit(bindings, copy);
  return true;
}

export function matchNode(pattern: AstNode, node: AstNode, bindings: Bindings = new Map()): boolean {
  const copy: Bindings = new Map(bindings);
  if (!matchRaw(pattern, node, copy)) {return false;}
  commit(bindings, copy);
  return true;
}

function parentOf(node: AstNode): AstNode | undefined {
  return (node as { parent?: AstNode }).parent;
}

function insideMatch(node: AstNode, insides: readonly AstNode[], bindings: Bindings): boolean {
  if (insides.length === 0) {return true;}
  let parent = parentOf(node);
  while (parent !== undefined) {
    for (const inside of insides) {
      if (matchNode(inside, parent, new Map(bindings))) {return true;}
    }
    parent = parentOf(parent);
  }
  return false;
}

function excluded(node: AstNode, patterns: readonly AstNode[]): boolean {
  return patterns.some((pattern) => matchNode(pattern, node));
}

export function searchHits(rule: CompiledSemgrepRule, ast: AstNode): AstNode[] {
  const patterns = rule.patternEither.length > 0 ? rule.patternEither : rule.pattern !== undefined ? [rule.pattern] : [];
  const hits: AstNode[] = [];
  walk(ast, (node) => {
    for (const pattern of patterns) {
      const bindings: Bindings = new Map();
      if (!matchNode(pattern, node, bindings)) {continue;}
      if (excluded(node, rule.patternNot)) {continue;}
      if (!insideMatch(node, rule.patternInside, bindings)) {continue;}
      hits.push(node);
      return;
    }
  });
  return hits;
}

function earlierWrite(from: AstNode, name: string, before: number): AstNode | undefined {
  const scope = enclosingScope(from);
  let best: { end: number; init: AstNode } | undefined;
  walk(scope, (node) => {
    if (node !== scope && enclosingScope(node) !== scope) {return;}
    if (node.range === undefined || node.range[1] > before) {return;}
    let init: AstNode | undefined;
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.id.name === name) {
      init = node.init ?? undefined;
    } else if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier' && node.left.name === name) {
      init = node.right;
    }
    if (init?.range === undefined) {return;}
    if (best === undefined || init.range[1] >= best.end) {best = { end: init.range[1], init };}
  });
  return best?.init;
}

function matchesAny(node: AstNode, patterns: readonly AstNode[]): boolean {
  return patterns.some((pattern) => matchNode(pattern, node));
}

function taintedValue(
  node: AstNode,
  rule: CompiledSemgrepRule,
  facts: WeakMap<AstNode, ScopeFacts>,
  seen: Set<AstNode>,
): boolean {
  if (seen.has(node)) {return false;}
  seen.add(node);
  if (matchesAny(node, rule.sanitizers)) {return false;}
  if (node.type === 'Identifier' && node.range !== undefined) {
    const init = earlierWrite(node, node.name, node.range[0]);
    if (init !== undefined) {return taintedValue(init, rule, facts, seen);}
  }
  if (nodeIsTainted(node, facts)) {return true;}
  return matchesAny(node, rule.sources);
}

export function taintHits(
  rule: CompiledSemgrepRule,
  ast: AstNode,
  facts: WeakMap<AstNode, ScopeFacts>,
): AstNode[] {
  const hits: AstNode[] = [];
  walk(ast, (node) => {
    for (const sink of rule.sinks) {
      const bindings: Bindings = new Map();
      if (!matchNode(sink, node, bindings)) {continue;}
      const values = [...bindings.values()];
      const targets = values.length > 0 ? values : [node];
      if (targets.some((target) => taintedValue(target, rule, facts, new Set()))) {hits.push(node);}
      return;
    }
  });
  return hits;
}
