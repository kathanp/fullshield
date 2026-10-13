import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { calleeName, literalString } from '../ast.js';
import type { SastRule } from '../types.js';

function algorithmsOption(node: TSESTree.CallExpression): TSESTree.Expression | undefined {
  const opts = node.arguments[2];
  if (opts === undefined || opts.type !== 'ObjectExpression') return undefined;
  for (const prop of opts.properties) {
    if (prop.type !== 'Property') continue;
    const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
    if (key === 'algorithms') return prop.value as TSESTree.Expression;
  }
  return undefined;
}

function includesNone(expr: TSESTree.Expression): boolean {
  if (expr.type !== 'ArrayExpression') return false;
  return expr.elements.some(
    (el) => el !== null && el.type === 'Literal' && (el.value === 'none' || el.value === 'None'),
  );
}

export const jwtRule: SastRule = {
  meta: {
    id: 'SAST-JWT-001',
    title: 'Insecure JWT verification',
    severity: 'high',
    cwe: 'CWE-347',
    docs: 'https://cwe.mitre.org/data/definitions/347.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') return;
        if (node.callee.type !== 'MemberExpression') return;
        const obj = node.callee.object;
        if (obj.type !== 'Identifier' || !/^(jwt|jsonwebtoken)$/i.test(obj.name)) return;
        const name = calleeName(node);
        if (name === 'decode') {
          ctx.report({
            node,
            message: 'jwt.decode is used; it does not verify the signature (verify is missing).',
          });
          return;
        }
        if (name !== 'verify') return;
        const algorithms = algorithmsOption(node);
        if (algorithms === undefined) {
          ctx.report({
            node,
            message: 'jwt.verify is called without an algorithms allow-list.',
          });
          return;
        }
        if (includesNone(algorithms)) {
          ctx.report({
            node,
            message: 'jwt.verify allows the "none" algorithm.',
          });
        }
      },
    };
  },
};
