import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { calleeName, isFunctionNode, literalString, walk } from '../ast.js';
import type { AstNode, SastRule } from '../types.js';

const ROUTES = new Set(['get', 'post', 'put', 'patch', 'delete', 'all']);
const AUTH_NAME = /auth|login|requireUser|requireAuth|authenticate|authorize|passport/i;
const DB_TOUCH = new Set(['query', 'find', 'findOne', 'create', 'update', 'delete', 'save', 'insert']);

function isRouteCall(node: TSESTree.CallExpression): boolean {
  if (node.callee.type !== 'MemberExpression') return false;
  const name = calleeName(node);
  if (name === undefined || !ROUTES.has(name)) return false;
  const obj = node.callee.object;
  return obj.type === 'Identifier' && /^(app|router)$/i.test(obj.name);
}

function hasAuthMiddleware(node: TSESTree.CallExpression): boolean {
  return node.arguments.some((arg) => {
    if (arg.type === 'Identifier') return AUTH_NAME.test(arg.name);
    return false;
  });
}

function handlerTouchesDb(handler: AstNode): boolean {
  let touches = false;
  walk(handler, (child) => {
    if (child.type === 'CallExpression' && calleeName(child) !== undefined && DB_TOUCH.has(calleeName(child) ?? '')) {
      touches = true;
    }
  });
  return touches;
}

export const authRule: SastRule = {
  meta: {
    id: 'SAST-AUTH-001',
    title: 'Route touches data with no auth middleware',
    severity: 'low',
    cwe: 'CWE-862',
    docs: 'https://cwe.mitre.org/data/definitions/862.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression' || !isRouteCall(node)) return;
        if (hasAuthMiddleware(node)) return;
        const handler = [...node.arguments].reverse().find((arg) => isFunctionNode(arg));
        if (handler === undefined || !handlerTouchesDb(handler)) return;
        const path = literalString(node.arguments[0]);
        ctx.report({
          node,
          message: `Route ${path ?? '(dynamic)'} touches database/user data with no auth middleware in the chain.`,
        });
      },
    };
  },
};
