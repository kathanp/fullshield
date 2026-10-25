import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { calleeName, literalString, propName } from '../ast.js';
import { sastGapsEnabled } from '../experimental.js';
import type { AstNode, SastRule } from '../types.js';

const ALWAYS_SHELL = new Set(['exec', 'execSync']);
const OPTIONAL_SHELL = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync']);
const INTERPRETERS = new Set(['sh', 'bash', 'zsh', 'dash', 'cmd', 'cmd.exe', 'powershell', 'pwsh']);
const DASH_C_CALLEES = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync', 'execa']);

function optionsObject(node: TSESTree.CallExpression): TSESTree.ObjectExpression | undefined {
  for (const arg of node.arguments) {
    if (arg.type === 'ObjectExpression') {return arg;}
  }
  return undefined;
}

function hasShellTrue(node: TSESTree.CallExpression): boolean {
  const opts = optionsObject(node);
  if (opts === undefined) {return false;}
  for (const prop of opts.properties) {
    if (prop.type !== 'Property') {continue;}
    const key =
      prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
    if (key !== 'shell') {continue;}
    return prop.value.type === 'Literal' && prop.value.value === true;
  }
  return false;
}

function argumentTainted(node: TSESTree.CallExpression, isTainted: (n: AstNode) => boolean): boolean {
  for (const arg of node.arguments) {
    if (arg.type === 'SpreadElement') {continue;}
    if (arg.type === 'ObjectExpression') {continue;}
    if (isTainted(arg)) {return true;}
    if (arg.type === 'ArrayExpression') {
      for (const el of arg.elements) {
        if (el !== null && el.type !== 'SpreadElement' && isTainted(el)) {return true;}
      }
    }
  }
  return false;
}

function interpreterBase(node: TSESTree.CallExpression): string | undefined {
  const cmd = literalString(node.arguments[0]);
  if (cmd === undefined) {return undefined;}
  return cmd.replace(/^.*[/\\]/, '').toLowerCase();
}

function isInterpreterDashC(node: TSESTree.CallExpression, isTainted: (n: AstNode) => boolean): boolean {
  const name = calleeName(node);
  if (name === undefined || !DASH_C_CALLEES.has(name)) {return false;}
  const base = interpreterBase(node);
  if (base === undefined || !INTERPRETERS.has(base)) {return false;}
  const args = node.arguments[1];
  if (args === undefined || args.type !== 'ArrayExpression') {return false;}
  for (let i = 0; i < args.elements.length; i += 1) {
    const el = args.elements[i];
    if (el === null || el === undefined || el.type === 'SpreadElement') {continue;}
    if (literalString(el) !== '-c') {continue;}
    const next = args.elements[i + 1];
    return next !== null && next !== undefined && next.type !== 'SpreadElement' && isTainted(next);
  }
  return false;
}

function isUnsafeZxTag(tag: AstNode): boolean {
  if (tag.type === 'MemberExpression' && propName(tag) === 'raw') {
    return tag.object.type === 'Identifier' && tag.object.name === '$';
  }
  if (tag.type === 'CallExpression' && tag.callee.type === 'Identifier' && tag.callee.name === '$') {
    const opts = tag.arguments[0];
    if (opts === undefined || opts.type !== 'ObjectExpression') {return false;}
    for (const prop of opts.properties) {
      if (prop.type !== 'Property') {continue;}
      const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
      if (key === 'quote' && prop.value.type === 'Literal' && prop.value.value === false) {return true;}
    }
  }
  return false;
}

function isBunSpawn(node: TSESTree.CallExpression): boolean {
  if (node.callee.type !== 'MemberExpression') {return false;}
  const object = node.callee.object;
  if (object.type !== 'Identifier' || object.name !== 'Bun') {return false;}
  const name = calleeName(node);
  return name === 'spawn' || name === 'spawnSync';
}

function arrayTainted(node: AstNode, isTainted: (n: AstNode) => boolean): boolean {
  if (node.type !== 'ArrayExpression') {return false;}
  for (const el of node.elements) {
    if (el !== null && el.type !== 'SpreadElement' && isTainted(el)) {return true;}
  }
  return false;
}

function commandFieldsTainted(node: AstNode, isTainted: (n: AstNode) => boolean): boolean {
  if (node.type !== 'ObjectExpression') {return false;}
  for (const prop of node.properties) {
    if (prop.type !== 'Property') {continue;}
    const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
    if (key !== 'cmd' && key !== 'args') {continue;}
    if (isTainted(prop.value) || arrayTainted(prop.value, isTainted)) {return true;}
  }
  return false;
}

function isBunTemplate(tag: AstNode, source: string): boolean {
  if (tag.type === 'MemberExpression' && propName(tag) === '$') {
    return tag.object.type === 'Identifier' && tag.object.name === 'Bun';
  }
  return tag.type === 'Identifier' && tag.name === '$' && /['"]bun['"]/.test(source);
}

function isDenoCommand(node: TSESTree.NewExpression): boolean {
  if (node.callee.type !== 'MemberExpression' || propName(node.callee) !== 'Command') {return false;}
  const object = node.callee.object;
  return object.type === 'Identifier' && object.name === 'Deno';
}

function denoTainted(node: TSESTree.NewExpression, isTainted: (n: AstNode) => boolean): boolean {
  const first = node.arguments[0];
  if (first !== undefined && first.type !== 'SpreadElement' && isTainted(first)) {return true;}
  const second = node.arguments[1];
  return second !== undefined && commandFieldsTainted(second, isTainted);
}

function isExecaShellTag(tag: AstNode): boolean {
  return tag.type === 'CallExpression' && calleeName(tag) === 'execa' && hasShellTrue(tag);
}

function bunSpawnTainted(node: TSESTree.CallExpression, isTainted: (n: AstNode) => boolean): boolean {
  if (!isBunSpawn(node)) {return false;}
  if (argumentTainted(node, isTainted)) {return true;}
  const options = node.arguments.find((arg) => arg.type === 'ObjectExpression');
  return options !== undefined && commandFieldsTainted(options, isTainted);
}

function shellRequested(
  node: TSESTree.CallExpression,
  name: string,
  isTainted: (n: AstNode) => boolean,
): { dashC: boolean; execaCall: boolean } | undefined {
  const dashC = sastGapsEnabled() && isInterpreterDashC(node, isTainted);
  const execaCall = sastGapsEnabled() && name === 'execa' && hasShellTrue(node);
  const shell = ALWAYS_SHELL.has(name) || (OPTIONAL_SHELL.has(name) && hasShellTrue(node)) || dashC || execaCall;
  if (!shell) {return undefined;}
  return { dashC, execaCall };
}

function execFilePathTainted(node: TSESTree.CallExpression, isTainted: (n: AstNode) => boolean): boolean {
  const name = calleeName(node);
  if (name !== 'execFile' && name !== 'execFileSync') {return false;}
  const first = node.arguments[0];
  if (first === undefined || first.type === 'SpreadElement') {return false;}
  return isTainted(first);
}

function memberAllowed(
  node: TSESTree.CallExpression,
  name: string,
  dashC: boolean,
  execaCall: boolean,
): boolean {
  if (node.callee.type !== 'MemberExpression') {return true;}
  const obj = node.callee.object;
  const fromChild =
    (obj.type === 'Identifier' && (obj.name === 'child_process' || obj.name === 'cp')) ||
    propName(node.callee) !== undefined;
  if (fromChild || ALWAYS_SHELL.has(name) || OPTIONAL_SHELL.has(name) || dashC || execaCall) {return true;}
  return false;
}

export const cmdiRule: SastRule = {
  meta: {
    id: 'SAST-CMDI-001',
    title: 'Command injection via shell execution',
    severity: 'high',
    cwe: 'CWE-78',
    docs: 'https://cwe.mitre.org/data/definitions/78.html',
  },
  create(ctx) {
    const tainted = (n: AstNode) => ctx.isTainted(n);
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name === undefined) {return;}
        if (execFilePathTainted(node, tainted)) {
          ctx.report({ node, message: 'Tainted input is the execFile command path.' });
          return;
        }
        if (bunSpawnTainted(node, tainted)) {
          ctx.report({ node, message: 'Tainted input reaches Bun.spawn.' });
          return;
        }
        const shell = shellRequested(node, name, tainted);
        if (shell === undefined || !memberAllowed(node, name, shell.dashC, shell.execaCall)) {return;}
        if (!argumentTainted(node, tainted) && !shell.dashC) {return;}
        ctx.report({
          node,
          message: 'Tainted input reaches a shell command (exec/execSync/spawn with shell: true).',
        });
      },
      NewExpression(node) {
        if (node.type !== 'NewExpression' || !isDenoCommand(node) || !denoTainted(node, tainted)) {return;}
        ctx.report({
          node,
          message: 'Tainted input reaches Deno.Command.',
        });
      },
      TaggedTemplateExpression(node) {
        if (node.type !== 'TaggedTemplateExpression') {return;}
        const bun = isBunTemplate(node.tag, ctx.source);
        if (!bun && !sastGapsEnabled()) {return;}
        if (!bun && !isUnsafeZxTag(node.tag) && !isExecaShellTag(node.tag)) {return;}
        if (!tainted(node.quasi)) {return;}
        ctx.report({
          node,
          message: 'Tainted input reaches a shell tagged template that does not auto-escape interpolations.',
        });
      },
    };
  },
};
