import { calleeName } from '../ast.js';
import type { AstNode, SastRule } from '../types.js';

export const redirectRule: SastRule = {
  meta: {
    id: 'SAST-REDIRECT-001',
    title: 'Open redirect',
    severity: 'high',
    cwe: 'CWE-601',
    docs: 'https://cwe.mitre.org/data/definitions/601.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        if (calleeName(node) !== 'redirect') {return;}
        const target = node.arguments[0];
        if (target === undefined || target.type === 'SpreadElement') {return;}
        if (!ctx.isTainted(target) || ctx.isSanitizedFor(target, 'url')) {return;}
        ctx.report({
          node,
          message: 'Tainted input is passed to res.redirect.',
        });
      },
    };
  },
};

function identifierName(node: AstNode | undefined): string | undefined {
  return node?.type === 'Identifier' ? node.name : undefined;
}

/** `url.includes(allowedUrl)` accepts any string that contains an allowlist entry. */
function isAllowlistIncludes(node: AstNode): boolean {
  if (node.type !== 'CallExpression') {return false;}
  const callee = node.callee;
  if (callee?.type !== 'MemberExpression' || callee.computed === true) {return false;}
  if (callee.property?.type !== 'Identifier' || callee.property.name !== 'includes') {return false;}
  const objectName = identifierName(callee.object);
  const argName = identifierName(node.arguments?.[0]);
  if (objectName === undefined || argName === undefined) {return false;}
  if (!/url|uri|href|redirect/i.test(objectName)) {return false;}
  return /allow|whitelist|permit|trusted/i.test(argName);
}

export const redirectAllowlistRule: SastRule = {
  meta: {
    id: 'SAST-REDIRECT-002',
    title: 'Redirect allowlist uses includes()',
    severity: 'medium',
    cwe: 'CWE-601',
    docs: 'https://cwe.mitre.org/data/definitions/601.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression' || !isAllowlistIncludes(node)) {return;}
        ctx.report({
          node,
          message: 'A redirect allowlist check uses includes(), so a longer string can pass.',
        });
      },
    };
  },
};
