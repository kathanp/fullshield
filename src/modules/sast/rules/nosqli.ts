import { calleeName, literalString } from '../ast.js';
import { isCoercionCall, isMongoSanitizeCall, isSchemaValidatorCall } from '../taint.js';
import type { AstNode, SastRule } from '../types.js';

const MONGO_SINKS = new Set([
  'find',
  'findOne',
  'findOneAndUpdate',
  'update',
  'updateOne',
  'updateMany',
  'deleteOne',
  'deleteMany',
  'remove',
  'aggregate',
]);

function objectKey(prop: { type: string; key?: AstNode }): string | undefined {
  if (prop.type !== 'Property' || prop.key === undefined) return undefined;
  const key = prop.key;
  if (key.type === 'Identifier') return key.name;
  if (key.type === 'Literal') return String(key.value);
  return literalString(key);
}

function objectHasKey(node: AstNode, name: string): boolean {
  if (node.type !== 'ObjectExpression') return false;
  return node.properties.some((prop) => objectKey(prop) === name);
}

/** Sequelize/TypeORM `update(values, { where })` / `find({ where })` — not a Mongo filter. */
function looksLikeSqlOrm(call: AstNode, filter: AstNode): boolean {
  if (call.type !== 'CallExpression') return false;
  if (objectHasKey(filter, 'where')) return true;
  const second = call.arguments[1];
  return second !== undefined && second.type !== 'SpreadElement' && objectHasKey(second, 'where');
}

function objectHasTaintedWhere(node: AstNode, isTainted: (n: AstNode) => boolean): boolean {
  if (node.type !== 'ObjectExpression') return false;
  for (const prop of node.properties) {
    if (prop.type !== 'Property') continue;
    const key =
      prop.key.type === 'Identifier'
        ? prop.key.name
        : prop.key.type === 'Literal'
          ? String(prop.key.value)
          : literalString(prop.key);
    if (key === '$where' && isTainted(prop.value)) return true;
  }
  return false;
}

function fileHasMongoSanitizeMiddleware(source: string): boolean {
  return (
    /(?:express-)?mongo-sanitize/.test(source) &&
    /(?:app|router)\.use\(\s*(?:mongoSanitize|sanitize)\s*\(/.test(source)
  );
}

function isSanitizeWrap(node: AstNode, source: string): boolean {
  if (node.type !== 'CallExpression') return false;
  const name = calleeName(node);
  return name === 'sanitize' && /(?:express-)?mongo-sanitize/.test(source);
}

function isNosqlSafeValue(
  node: AstNode,
  source: string,
  isNosqlSanitized: (n: AstNode) => boolean,
): boolean {
  if (isNosqlSanitized(node) || isCoercionCall(node) || isSchemaValidatorCall(node) || isMongoSanitizeCall(node)) {
    return true;
  }
  return isSanitizeWrap(node, source);
}

function objectHasUnsafeTaintedValue(
  node: AstNode,
  isTainted: (n: AstNode) => boolean,
  isSafe: (n: AstNode) => boolean,
): boolean {
  if (node.type === 'ArrayExpression') {
    return node.elements.some((el) => el !== null && el.type !== 'SpreadElement' && objectHasUnsafeTaintedValue(el, isTainted, isSafe));
  }
  if (node.type !== 'ObjectExpression') return false;
  for (const prop of node.properties) {
    if (prop.type !== 'Property') continue;
    const value = prop.value;
    if (isSafe(value)) continue;
    if (isTainted(value)) return true;
    if (objectHasUnsafeTaintedValue(value, isTainted, isSafe)) return true;
  }
  return false;
}

export const nosqliRule: SastRule = {
  meta: {
    id: 'SAST-NOSQLI-001',
    title: 'NoSQL injection via raw request object filter',
    severity: 'high',
    cwe: 'CWE-943',
    docs: 'https://cwe.mitre.org/data/definitions/943.html',
  },
  create(ctx) {
    const middleware = fileHasMongoSanitizeMiddleware(ctx.source);
    const isSafe = (n: AstNode) => isNosqlSafeValue(n, ctx.source, (x) => ctx.isNosqlSanitized(x));
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') return;
        const name = calleeName(node);
        if (name === '$where') {
          const expr = node.arguments[0];
          if (expr !== undefined && expr.type !== 'SpreadElement' && ctx.isTainted(expr)) {
            ctx.report({
              node,
              message: 'Tainted input is passed to mongoose $where (server-side JS).',
            });
          }
          return;
        }
        if (name === undefined || !MONGO_SINKS.has(name)) return;
        const filter = node.arguments[0];
        if (filter === undefined || filter.type === 'SpreadElement') return;
        if (ctx.isRequestObject(filter)) {
          ctx.report({
            node,
            message: 'req.body/req.query is passed directly into a Mongo-style filter.',
          });
          return;
        }
        if (objectHasTaintedWhere(filter, (n) => ctx.isTainted(n))) {
          ctx.report({
            node,
            message: 'Tainted input is passed to a Mongo $where filter.',
          });
          return;
        }
        if (middleware) return;
        if (looksLikeSqlOrm(node, filter)) return;
        if (objectHasUnsafeTaintedValue(filter, (n) => ctx.isTainted(n), isSafe)) {
          ctx.report({
            node,
            message: 'Request input is used as a Mongo filter value without coercion, schema validation, or mongo-sanitize.',
            confidence: 'medium',
          });
        }
      },
    };
  },
};
