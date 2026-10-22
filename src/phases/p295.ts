import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { parseProgram, propName, stripNode, walkAst, type UnsoundEvent } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_NEXTACTION';

const AUTH = new Set(['requireAuth', 'ensureAuth', 'authenticate', 'isAuthenticated', 'getServerSession', 'auth']);

export interface ActionFinding {
  file: string;
  action: string;
  injection: boolean;
  authState: 'present' | 'absent';
  pages: string[];
  caller: string;
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeServerActions(files: Readonly<Record<string, string>>): { findings: ActionFinding[]; events: UnsoundEvent[] } {
  if (!enabled()) {return { findings: [], events: [] };}
  const events: UnsoundEvent[] = [];
  const findings: ActionFinding[] = [];
  const actions = new Map<string, { file: string; name: string; params: string[]; auth: boolean; formData: boolean; dynamicKey: boolean; queriesParam: boolean }>();
  for (const [file, source] of Object.entries(files)) {
    const program = parseProgram(source);
    if (program === null || !isServerModule(program)) {continue;}
    for (const stmt of program.body) {
      if (stmt.type !== 'ExportNamedDeclaration' || stmt.declaration?.type !== 'FunctionDeclaration' || stmt.declaration.id === null || !stmt.declaration.async) {continue;}
      const fn = stmt.declaration;
      if (fn.id === null) {continue;}
      const name = fn.id.name;
      const info = inspectAction(fn);
      if (info.dynamicKey) {events.push({ kind: 'dynamic-property', file, line: 1, reason: 'dynamic form key' });}
      actions.set(name, { file, name, ...info });
    }
    if (hasComputedAction(program)) {events.push({ kind: 'dynamic-property', file, line: 1, reason: 'computed action id' });}
  }
  for (const action of actions.values()) {
    const pages: string[] = [];
    let literalOnly = true;
    let sawCall = false;
    for (const [file, source] of Object.entries(files)) {
      if (file === action.file) {continue;}
      const program = parseProgram(source);
      if (program === null || !importsName(program, action.name)) {continue;}
      if (!references(program, action.name)) {continue;}
      pages.push(file);
      const calls = callsOf(program, action.name);
      if (calls.length > 0) {sawCall = true;}
      if (calls.some((call) => call.arguments.some((arg) => arg.type !== 'Literal'))) {literalOnly = false;}
    }
    const injection = action.formData || (action.queriesParam && !(sawCall && literalOnly));
    if (!injection) {continue;}
    findings.push({
      file: action.file,
      action: action.name,
      injection: true,
      authState: action.auth ? 'present' : 'absent',
      pages,
      caller: pages.length === 0 ? 'unknown' : pages.join(','),
    });
  }
  return { findings, events };
}

function isServerModule(program: TSESTree.Program): boolean {
  const first = program.body[0];
  return first !== undefined && first.type === 'ExpressionStatement' && first.expression.type === 'Literal' && first.expression.value === 'use server';
}

function inspectAction(fn: TSESTree.FunctionDeclaration): { params: string[]; auth: boolean; formData: boolean; dynamicKey: boolean; queriesParam: boolean } {
  const params = fn.params.flatMap((param) => param.type === 'Identifier' ? [param.name] : []);
  let auth = false;
  let formData = false;
  let dynamicKey = false;
  let queriesParam = false;
  const body = fn.body.body;
  for (const stmt of body) {
    if (!auth && callsAuth(stmt)) {auth = true;}
    if (stmt.type === 'ExpressionStatement' && stmt.expression.type === 'CallExpression') {
      const arg = stmt.expression.arguments[0];
      if (arg !== undefined && usesFormData(arg)) {formData = true;}
      if (arg !== undefined && arg.type === 'Identifier' && params.includes(arg.name)) {queriesParam = true;}
      if (arg !== undefined && arg.type === 'BinaryExpression') {
        if (usesFormData(arg)) {formData = true;}
        if (params.some((name) => containsIdent(arg, name))) {queriesParam = true;}
      }
    }
  }
  walkAst(fn, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression' && (propName(node.callee) === 'get' || propName(node.callee) === 'getAll')) {
      const key = node.arguments[0];
      if (key !== undefined && key.type === 'Literal') {formData = true;}
      if (key !== undefined && key.type !== 'Literal' && key.type !== 'SpreadElement') {dynamicKey = true; formData = true;}
    }
  });
  return { params, auth, formData, dynamicKey, queriesParam };
}

function callsAuth(stmt: TSESTree.Statement): boolean {
  let found = false;
  walkAst(stmt, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && AUTH.has(node.callee.name)) {found = true;}
  });
  return found;
}

function usesFormData(node: TSESTree.Node): boolean {
  let found = false;
  walkAst(node, (current) => {
    if (current.type === 'CallExpression' && current.callee.type === 'MemberExpression' && (propName(current.callee) === 'get' || propName(current.callee) === 'getAll')) {found = true;}
  });
  return found;
}

function containsIdent(node: TSESTree.Node, name: string): boolean {
  let found = false;
  walkAst(node, (current) => {
    if (current.type === 'Identifier' && current.name === name) {found = true;}
  });
  return found;
}

function importsName(program: TSESTree.Program, name: string): boolean {
  return program.body.some((stmt) => stmt.type === 'ImportDeclaration' && stmt.specifiers.some((spec) => spec.type === 'ImportSpecifier' && spec.local.name === name));
}

function references(program: TSESTree.Program, name: string): boolean {
  let found = false;
  walkAst(program, (node) => {
    if (node.type === 'Identifier' && node.name === name) {found = true;}
  });
  return found;
}

function callsOf(program: TSESTree.Program, name: string): TSESTree.CallExpression[] {
  const calls: TSESTree.CallExpression[] = [];
  walkAst(program, (node) => {
    if (node.type === 'CallExpression') {
      const callee = stripNode(node.callee);
      if (callee.type === 'Identifier' && callee.name === name) {calls.push(node);}
    }
  });
  return calls;
}

function hasComputedAction(program: TSESTree.Program): boolean {
  let found = false;
  walkAst(program, (node) => {
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression' && node.callee.computed && node.callee.property.type !== 'Literal') {found = true;}
  });
  return found;
}
