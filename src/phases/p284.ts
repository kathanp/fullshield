import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isRequestSource, lineOf, parseProgram, propName, stripNode, walkAst } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_REDOS2';

export interface RedosAttack {
  prefix: string;
  pump: string;
  suffix: string;
}

export interface RedosFinding {
  file: string;
  line: number;
  ruleId: 'SAST-REDOS-001';
  ambiguity: 'exponential' | 'polynomial';
  subpattern: string;
  attack: RedosAttack;
  documentedResidual: boolean;
}

type Rx =
  | { type: 'eps'; start: number; end: number }
  | { type: 'atom'; atom: string; start: number; end: number }
  | { type: 'cat'; parts: Rx[]; start: number; end: number }
  | { type: 'alt'; options: Rx[]; start: number; end: number }
  | { type: 'rep'; body: Rx; unbounded: boolean; start: number; end: number }
  | { type: 'unknown'; start: number; end: number };

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeRedos(source: string, options?: { file?: string }): { findings: RedosFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  const patterns = new Map<string, string>();
  const findings: RedosFinding[] = [];
  for (const stmt of program.body) {collectPatterns(stmt, patterns);}
  walkAst(program, (node) => {
    if (node.type !== 'CallExpression') {return;}
    const use = regexUse(node, patterns);
    if (use === null || !subjectTainted(use.subject)) {return;}
    const parsed = parsePattern(use.pattern);
    if (parsed.type === 'unknown') {return;}
    const kind = ambiguity(parsed);
    if (kind === 'none') {return;}
    const attack = attackShape(parsed, use.pattern);
    if (attack === null) {return;}
    if (!classPermits(use.subject, attack.pump)) {return;}
    findings.push({
      file,
      line: lineOf(node),
      ruleId: 'SAST-REDOS-001',
      ambiguity: kind,
      subpattern: use.pattern.slice(attack.start, attack.end),
      attack: { prefix: attack.prefix, pump: attack.pump, suffix: attack.suffix },
      documentedResidual: hasLengthGuard(program),
    });
  });
  return { findings };
}

function collectPatterns(stmt: TSESTree.Statement, patterns: Map<string, string>): void {
  if (stmt.type === 'FunctionDeclaration') {
    for (const inner of stmt.body.body) {collectPatterns(inner, patterns);}
  }
  if (stmt.type === 'VariableDeclaration') {
    for (const decl of stmt.declarations) {
      if (decl.id.type !== 'Identifier' || decl.init === null) {continue;}
      const pattern = literalPattern(decl.init);
      if (pattern !== null) {patterns.set(decl.id.name, pattern);}
    }
  }
}

function literalPattern(node: TSESTree.Node): string | null {
  const current = stripNode(node);
  if (current.type === 'Literal' && 'regex' in current && current.regex !== null && current.regex !== undefined) {return current.regex.pattern;}
  if (current.type === 'NewExpression' && current.callee.type === 'Identifier' && current.callee.name === 'RegExp') {
    const arg = current.arguments[0];
    if (arg !== undefined && arg.type === 'Literal' && typeof arg.value === 'string') {return arg.value;}
  }
  return null;
}

function regexUse(call: TSESTree.CallExpression, patterns: ReadonlyMap<string, string>): { pattern: string; subject: TSESTree.Node } | null {
  const callee = stripNode(call.callee);
  if (callee.type !== 'MemberExpression') {return null;}
  const name = propName(callee);
  const arg0 = call.arguments[0];
  if (name === 'test' || name === 'exec') {
    const pattern = patternOf(callee.object, patterns);
    if (pattern === null || arg0 === undefined || arg0.type === 'SpreadElement') {return null;}
    return { pattern, subject: arg0 };
  }
  if ((name === 'match' || name === 'replace' || name === 'split') && arg0 !== undefined && arg0.type !== 'SpreadElement') {
    const pattern = patternOf(arg0, patterns);
    if (pattern === null) {return null;}
    return { pattern, subject: callee.object };
  }
  return null;
}

function patternOf(node: TSESTree.Node, patterns: ReadonlyMap<string, string>): string | null {
  const direct = literalPattern(node);
  if (direct !== null) {return direct;}
  if (node.type === 'Identifier') {return patterns.get(node.name) ?? null;}
  return null;
}

function subjectTainted(node: TSESTree.Node): boolean {
  let hit = false;
  walkAst(node, (current) => {
    if (isRequestSource(current)) {hit = true;}
    if (current.type === 'Identifier' && current.name !== 'Number' && current.name !== 'String') {hit = true;}
  });
  return hit;
}

function classPermits(subject: TSESTree.Node, pump: string): boolean {
  const digits = pump >= '0' && pump <= '9';
  let numeric = false;
  walkAst(subject, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && (node.callee.name === 'Number' || node.callee.name === 'parseInt')) {
      numeric = true;
    }
  });
  if (numeric && !digits) {return false;}
  return true;
}

function hasLengthGuard(program: TSESTree.Program): boolean {
  let hit = false;
  walkAst(program, (node) => {
    if (node.type === 'BinaryExpression' && node.left.type === 'MemberExpression' && propName(node.left) === 'length') {hit = true;}
  });
  return hit;
}

export function parsePattern(pattern: string): Rx {
  if (/\\[1-9]/.test(pattern) || /\(\?<[=!]/.test(pattern)) {return { type: 'unknown', start: 0, end: 0 };}
  let i = 0;
  const parseAlt = (): Rx => {
    const start = i;
    const options = [parseCat()];
    while (pattern[i] === '|') {i += 1; options.push(parseCat());}
    if (options.length === 1) {return options[0] ?? { type: 'eps', start, end: i };}
    return { type: 'alt', options, start, end: i };
  };
  const parseCat = (): Rx => {
    const start = i;
    const parts: Rx[] = [];
    while (i < pattern.length && pattern[i] !== ')' && pattern[i] !== '|') {parts.push(parseQuant());}
    if (parts.length === 0) {return { type: 'eps', start, end: i };}
    if (parts.length === 1) {return parts[0] ?? { type: 'eps', start, end: i };}
    return { type: 'cat', parts, start, end: i };
  };
  const parseQuant = (): Rx => {
    const atom = parseAtom();
    const mark = pattern[i];
    if (mark === '*' || mark === '+' || mark === '?') {
      i += 1;
      return { type: 'rep', body: atom, unbounded: mark !== '?', start: atom.start, end: i };
    }
    if (mark === '{') {
      const close = pattern.indexOf('}', i);
      const body = close === -1 ? '' : pattern.slice(i + 1, close);
      if (close !== -1 && /^\d+(,\d*)?$/.test(body)) {
        i = close + 1;
        const unbounded = body.endsWith(',') || (body.includes(',') && body.split(',')[1] === '');
        return { type: 'rep', body: atom, unbounded, start: atom.start, end: i };
      }
    }
    return atom;
  };
  const parseAtom = (): Rx => {
    const start = i;
    const ch = pattern[i] ?? '';
    if (ch === '^' || ch === '$') {i += 1; return { type: 'eps', start, end: i };}
    if (ch === '.') {i += 1; return { type: 'atom', atom: 'any', start, end: i };}
    if (ch === '\\') {
      const esc = pattern[i + 1] ?? '';
      i += 2;
      if (esc === 'd') {return { type: 'atom', atom: 'digit', start, end: i };}
      if (esc === 'w') {return { type: 'atom', atom: 'word', start, end: i };}
      if (esc === 's') {return { type: 'atom', atom: 'space', start, end: i };}
      return { type: 'atom', atom: `lit:${esc}`, start, end: i };
    }
    if (ch === '[') {
      const close = pattern.indexOf(']', i + 1);
      const body = close === -1 ? '' : pattern.slice(i + 1, close);
      i = close === -1 ? pattern.length : close + 1;
      const atom = body.includes('0-9') || body === '\\d' ? 'digit' : body.includes('a-z') || body.includes('A-Z') ? 'letter' : `class:${body}`;
      return { type: 'atom', atom, start, end: i };
    }
    if (ch === '(') {
      i += 1;
      if (pattern.startsWith('?:', i)) {i += 2;}
      else if (pattern[i] === '?' && pattern[i + 1] === '<') {
        const endName = pattern.indexOf('>', i);
        if (endName !== -1 && pattern[i + 2] !== '=' && pattern[i + 2] !== '!') {i = endName + 1;}
      }
      const inner = parseAlt();
      if (pattern[i] === ')') {i += 1;}
      return inner.type === 'eps' ? inner : { ...inner, start, end: i };
    }
    i += 1;
    return { type: 'atom', atom: `lit:${ch}`, start, end: i };
  };
  const parsed = parseAlt();
  return i < pattern.length ? { type: 'unknown', start: 0, end: i } : parsed;
}

function ambiguity(rx: Rx): 'exponential' | 'polynomial' | 'none' {
  if (rx.type === 'unknown') {return 'none';}
  if (hasNested(rx)) {return 'exponential';}
  if (hasAdjacent(rx)) {return 'polynomial';}
  return 'none';
}

function hasNested(rx: Rx): boolean {
  if (rx.type === 'rep' && rx.unbounded && childReps(rx.body).some((rep) => rep.unbounded && intersects(alpha(rx.body), alpha(rep)))) {
    return true;
  }
  return children(rx).some((child) => hasNested(child));
}

function hasAdjacent(rx: Rx): boolean {
  if (rx.type === 'cat') {
    const reps = rx.parts.filter((part) => childReps(part).length > 0 || (part.type === 'rep' && part.unbounded));
    for (let i = 0; i < reps.length; i += 1) {
      for (let j = i + 1; j < reps.length; j += 1) {
        const left = reps[i];
        const right = reps[j];
        if (left !== undefined && right !== undefined && intersects(alpha(left), alpha(right))) {return true;}
      }
    }
  }
  return children(rx).some((child) => hasAdjacent(child));
}

function childReps(rx: Rx): Extract<Rx, { type: 'rep' }>[] {
  if (rx.type === 'rep') {return [rx, ...childReps(rx.body)];}
  return children(rx).flatMap((child) => childReps(child));
}

function children(rx: Rx): Rx[] {
  if (rx.type === 'cat') {return rx.parts;}
  if (rx.type === 'alt') {return rx.options;}
  if (rx.type === 'rep') {return [rx.body];}
  return [];
}

function alpha(rx: Rx): Set<string> {
  if (rx.type === 'atom') {return new Set([rx.atom]);}
  if (rx.type === 'rep') {return alpha(rx.body);}
  const out = new Set<string>();
  for (const child of children(rx)) {
    for (const item of alpha(child)) {out.add(item);}
  }
  return out;
}

function intersects(left: ReadonlySet<string>, right: ReadonlySet<string>): boolean {
  if (left.has('any') || right.has('any')) {return true;}
  for (const item of left) {
    if (right.has(item)) {return true;}
    if (item === 'word' && [...right].some((other) => other.startsWith('lit:') && /[A-Za-z0-9_]/.test(other.slice(4)))) {return true;}
    if (item === 'letter' && [...right].some((other) => other === 'letter' || (other.startsWith('lit:') && /[A-Za-z]/.test(other.slice(4))))) {return true;}
    if (item === 'digit' && (right.has('digit') || right.has('word'))) {return true;}
  }
  return false;
}

function attackShape(rx: Rx, pattern: string): { prefix: string; pump: string; suffix: string; start: number; end: number } | null {
  const target = findRep(rx);
  if (target === null) {return null;}
  const pump = pumpChar(alpha(target));
  const { prefix, suffix } = surroundings(rx, target);
  return { prefix, pump, suffix, start: target.start, end: target.end === target.start ? pattern.length : target.end };
}

function findRep(rx: Rx): Extract<Rx, { type: 'rep' }> | null {
  if (rx.type === 'rep' && rx.unbounded) {
    const inner = findRep(rx.body);
    return inner ?? rx;
  }
  for (const child of children(rx)) {
    const found = findRep(child);
    if (found !== null) {return found;}
  }
  return null;
}

function surroundings(rx: Rx, target: Rx): { prefix: string; suffix: string } {
  if (rx.type !== 'cat') {
    for (const child of children(rx)) {
      const found = surroundings(child, target);
      if (found.prefix !== '' || found.suffix !== '' || child === target) {return found;}
    }
    return { prefix: '', suffix: '' };
  }
  let seen = false;
  let prefix = '';
  let suffix = '';
  for (const part of rx.parts) {
    if (part === target || containsNode(part, target)) {
      seen = true;
      continue;
    }
    const text = literalText(part);
    if (!seen) {prefix += text;}
    else {suffix += text;}
  }
  return { prefix, suffix };
}

function containsNode(rx: Rx, target: Rx): boolean {
  if (rx === target) {return true;}
  return children(rx).some((child) => containsNode(child, target));
}

function literalText(rx: Rx): string {
  if (rx.type === 'atom' && rx.atom.startsWith('lit:')) {return rx.atom.slice(4);}
  if (rx.type === 'cat') {return rx.parts.map((part) => literalText(part)).join('');}
  return '';
}

function pumpChar(chars: ReadonlySet<string>): string {
  for (const item of chars) {
    if (item.startsWith('lit:')) {return item.slice(4, 5);}
  }
  if (chars.has('digit')) {return '0';}
  if (chars.has('letter') || chars.has('word')) {return 'a';}
  return 'a';
}
