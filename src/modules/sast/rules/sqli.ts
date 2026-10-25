import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { calleeChainHas, calleeName } from '../ast.js';
import { sastGapsEnabled } from '../experimental.js';
import type { SastRule } from '../types.js';

const STABLE_SQL_SINKS = new Set(['query', 'execute']);
const GAP_SQL_SINKS = new Set([
  '$queryRawUnsafe',
  '$executeRawUnsafe',
  'raw',
  'literal',
  'whereRaw',
  'orderByRaw',
]);

function hasBindings(node: TSESTree.CallExpression): boolean {
  const second = node.arguments[1];
  if (second === undefined || second.type === 'SpreadElement') {return false;}
  return second.type === 'ArrayExpression' || second.type === 'ObjectExpression';
}

function sqliteMember(node: TSESTree.CallExpression, source: string): boolean {
  const name = calleeName(node);
  if (name !== 'exec' && name !== 'prepare') {return false;}
  if (node.callee.type !== 'MemberExpression') {return false;}
  const object = node.callee.object;
  if (object.type === 'Identifier' && (object.name === 'child_process' || object.name === 'cp')) {return false;}
  return /node:sqlite|bun:sqlite|DatabaseSync/.test(source);
}

function isSqlSink(node: TSESTree.CallExpression): boolean {
  const name = calleeName(node);
  if (name === undefined) {return false;}
  if (STABLE_SQL_SINKS.has(name)) {return true;}
  if (!sastGapsEnabled()) {return false;}
  if (GAP_SQL_SINKS.has(name)) {
    if ((name === 'whereRaw' || name === 'orderByRaw') && hasBindings(node)) {return false;}
    return true;
  }
  if (name === 'where' && calleeChainHas(node, 'createQueryBuilder')) {
    const first = node.arguments[0];
    return first !== undefined && first.type !== 'ObjectExpression';
  }
  return false;
}

export const sqliRule: SastRule = {
  meta: {
    id: 'SAST-SQLI-001',
    title: 'SQL injection via string concatenation',
    severity: 'high',
    cwe: 'CWE-89',
    docs: 'https://cwe.mitre.org/data/definitions/89.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        if (!isSqlSink(node) && !sqliteMember(node, ctx.source)) {return;}
        const sql = node.arguments[0];
        if (sql !== undefined && sql.type !== 'SpreadElement' && ctx.isTainted(sql) && !ctx.isSqlCleared(sql)) {
          ctx.report({
            node,
            message: 'Tainted input is concatenated into a SQL string passed to query/execute.',
          });
        }
      },
    };
  },
};
