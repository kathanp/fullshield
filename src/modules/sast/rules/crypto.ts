import { calleeName, literalString, propName } from '../ast.js';
import type { SastRule } from '../types.js';

const TOKEN_NAME = /token|secret|session|password|passwd|pwd|(^|_)id$/i;
const WEAK_HASH = new Set(['md5', 'sha1']);

export const cryptoRule: SastRule = {
  meta: {
    id: 'SAST-CRYPTO-001',
    title: 'Weak cryptography for secrets or tokens',
    severity: 'medium',
    cwe: 'CWE-327',
    docs: 'https://cwe.mitre.org/data/definitions/327.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}

        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          node.callee.object.name === 'Math' &&
          propName(node.callee) === 'random'
        ) {
          const assigned = ctx.assignedName(node) ?? '';
          if (TOKEN_NAME.test(assigned)) {
            ctx.report({
              node,
              message: 'Math.random is used to generate a token or identifier.',
            });
          }
          return;
        }

        const name = calleeName(node);
        if (name === 'md5') {
          const arg = node.arguments[0];
          if (arg !== undefined && arg.type !== 'SpreadElement' && ctx.isTainted(arg)) {
            ctx.report({
              node,
              message: 'The md5 helper is used as a token or identifier over tainted input.',
            });
          }
          return;
        }
        if (name !== 'createHash') {return;}
        const algo = literalString(node.arguments[0]);
        if (algo === undefined || !WEAK_HASH.has(algo.toLowerCase())) {return;}
        if (!ctx.functionHasPasswordName(node)) {return;}
        ctx.report({
          node,
          message: `Weak hash ${algo} is used near a password.`,
        });
      },
    };
  },
};
