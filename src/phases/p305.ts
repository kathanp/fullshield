import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { lineOf, parseProgram, propName, stripNode, walkAst } from './p271.js';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CLI';

export interface CliFinding {
  file: string;
  line: number;
  origin: 'cli';
  severity: 'low';
  sinkClass: 'cmdi' | 'path' | 'eval';
}

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function analyzeCli(source: string, options?: { file?: string; bin?: boolean }): { findings: CliFinding[] } {
  if (!enabled()) {return { findings: [] };}
  const program = parseProgram(source);
  if (program === null) {return { findings: [] };}
  const file = options?.file ?? 'inline.js';
  if (!isCli(program, options?.bin === true)) {return { findings: [] };}
  const findings: CliFinding[] = [];
  walkAst(program, (node) => {noteCli(node, file, findings);});
  return { findings };
}

export function scanTreeForCli(root: string): CliFinding[] {
  if (!enabled()) {return [];}
  const findings: CliFinding[] = [];
  const visit = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      if (name === 'node_modules' || name === 'test' || name === 'tests') {continue;}
      const full = join(dir, name);
      const stat = statSync(full);
      if (stat.isDirectory()) {visit(full); continue;}
      if (!name.endsWith('.js') && !name.endsWith('.ts')) {continue;}
      const bin = name === 'package.json' ? false : packageHasBin(dir);
      findings.push(...analyzeCli(readFileSync(full, 'utf8'), { file: full, bin }).findings);
    }
  };
  visit(root);
  return findings;
}

function noteCli(node: TSESTree.Node, file: string, findings: CliFinding[]): void {
  if (node.type !== 'CallExpression') {return;}
  const name = cliCallee(stripNode(node.callee));
  const sinkClass = cliSink(name);
  if (sinkClass === null) {return;}
  const arg = node.arguments[0];
  if (arg === undefined || !usesCli(arg)) {return;}
  findings.push({ file, line: lineOf(node), origin: 'cli', severity: 'low', sinkClass });
}

function cliCallee(callee: TSESTree.Node): string | null {
  if (callee.type === 'Identifier') {return callee.name;}
  if (callee.type === 'MemberExpression') {return propName(callee);}
  return null;
}

function cliSink(name: string | null): CliFinding['sinkClass'] | null {
  if (name === 'query' || name === 'execFile' || name === null) {return null;}
  if (name === 'eval') {return 'eval';}
  if (name === 'readFile' || name === 'readFileSync') {return 'path';}
  if (name === 'exec' || name === 'execSync') {return 'cmdi';}
  return null;
}

function packageHasBin(dir: string): boolean {
  try {
    const text = readFileSync(join(dir, 'package.json'), 'utf8');
    const parsed: unknown = JSON.parse(text);
    return typeof parsed === 'object' && parsed !== null && 'bin' in parsed && parsed.bin !== undefined;
  } catch {
    return false;
  }
}

function isCli(program: TSESTree.Program, bin: boolean): boolean {
  if (bin) {return true;}
  let parser = false;
  walkAst(program, (node) => {
    if (node.type === 'CallExpression') {
      const callee = stripNode(node.callee);
      const name = callee.type === 'Identifier' ? callee.name : callee.type === 'MemberExpression' ? propName(callee) : null;
      if (name === 'command' || name === 'option' || name === 'Command') {parser = true;}
    }
    if (node.type === 'Identifier' && (node.name === 'commander' || node.name === 'yargs')) {parser = true;}
    if (node.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'Command') {parser = true;}
  });
  return parser;
}

function usesCli(node: TSESTree.Node): boolean {
  let found = false;
  walkAst(node, (current) => {
    if (current.type === 'CallExpression' && current.callee.type === 'MemberExpression' && (propName(current.callee) === 'opts' || propName(current.callee) === 'argv')) {found = true;}
    if (current.type === 'MemberExpression' && current.object.type === 'Identifier' && current.object.name === 'process' && propName(current) === 'argv') {found = true;}
  });
  return found;
}
