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
    if (el == null || el.type === 'SpreadElement') {continue;}
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

function isExecaShellTag(tag: AstNode): boolean {
  return tag.type === 'CallExpression' && calleeName(tag) === 'execa' && hasShellTrue(tag);
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
        const dashC = sastGapsEnabled() && isInterpreterDashC(node, tainted);
        const execaCall = sastGapsEnabled() && name === 'execa' && hasShellTrue(node);
        const shell =
          ALWAYS_SHELL.has(name) ||
          (OPTIONAL_SHELL.has(name) && hasShellTrue(node)) ||
          dashC ||
          execaCall;
        if (!shell) {return;}
        if (node.callee.type === 'MemberExpression') {
          const obj = node.callee.object;
          const fromChild =
            (obj.type === 'Identifier' && (obj.name === 'child_process' || obj.name === 'cp')) ||
            propName(node.callee) !== undefined;
          if (!fromChild && !ALWAYS_SHELL.has(name) && !OPTIONAL_SHELL.has(name) && !dashC && !execaCall) {
            return;
          }
        }
        if (!argumentTainted(node, tainted) && !dashC) {return;}
        ctx.report({
          node,
          message: 'Tainted input reaches a shell command (exec/execSync/spawn with shell: true).',
        });
      },
      TaggedTemplateExpression(node) {
        if (node.type !== 'TaggedTemplateExpression' || !sastGapsEnabled()) {return;}
        if (!isUnsafeZxTag(node.tag) && !isExecaShellTag(node.tag)) {return;}
        if (!tainted(node.quasi)) {return;}
        ctx.report({
          node,
          message: 'Tainted input reaches a shell tagged template that does not auto-escape interpolations.',
        });
      },
    };
  },
};
