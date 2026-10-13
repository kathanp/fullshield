import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { calleeName, literalString, propName } from '../ast.js';
import type { AstNode, SastRule } from '../types.js';

const ALWAYS_SHELL = new Set(['exec', 'execSync']);
const OPTIONAL_SHELL = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync']);

function optionsObject(node: TSESTree.CallExpression): TSESTree.ObjectExpression | undefined {
  for (const arg of node.arguments) {
    if (arg.type === 'ObjectExpression') return arg;
  }
  return undefined;
}

function hasShellTrue(node: TSESTree.CallExpression): boolean {
  const opts = optionsObject(node);
  if (opts === undefined) return false;
  for (const prop of opts.properties) {
    if (prop.type !== 'Property') continue;
    const key =
      prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
    if (key !== 'shell') continue;
    return prop.value.type === 'Literal' && prop.value.value === true;
  }
  return false;
}

function argumentTainted(node: TSESTree.CallExpression, isTainted: (n: AstNode) => boolean): boolean {
  for (const arg of node.arguments) {
    if (arg.type === 'SpreadElement') continue;
    if (arg.type === 'ObjectExpression') continue;
    if (isTainted(arg)) return true;
    if (arg.type === 'ArrayExpression') {
      for (const el of arg.elements) {
        if (el !== null && el.type !== 'SpreadElement' && isTainted(el)) return true;
      }
    }
  }
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
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') return;
        const name = calleeName(node);
        if (name === undefined) return;
        const shell =
          ALWAYS_SHELL.has(name) || (OPTIONAL_SHELL.has(name) && hasShellTrue(node));
        if (!shell) return;
        // Prefer the callee object look: child_process.exec / bare exec / spawn.
        if (node.callee.type === 'MemberExpression') {
          const obj = node.callee.object;
          const fromChild =
            (obj.type === 'Identifier' && (obj.name === 'child_process' || obj.name === 'cp')) ||
            propName(node.callee) !== undefined;
          if (!fromChild && !ALWAYS_SHELL.has(name) && !OPTIONAL_SHELL.has(name)) return;
        }
        if (!argumentTainted(node, (n) => ctx.isTainted(n))) return;
        ctx.report({
          node,
          message: 'Tainted input reaches a shell command (exec/execSync/spawn with shell: true).',
        });
      },
    };
  },
};
