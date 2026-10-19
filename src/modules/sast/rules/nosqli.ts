import { calleeName, literalString, propName } from '../ast.js';
import { isCoercionCall, isMongoSanitizeCall, isSchemaValidatorCall } from '../taint.js';
import type { AstNode, SastRule } from '../types.js';
import { isValidatedRouteField } from '../validation.js';

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

/** Prisma / Sequelize / TypeORM method names that are never Mongo. */
const SQL_ONLY_METHODS = new Set([
  'findUnique',
  'findMany',
  'findFirst',
  'findAll',
  'findAndCountAll',
  'findByPk',
  'findById',
]);

const SQL_ORM_IMPORT = /(?:from|require\s*\(\s*)['"](?:sequelize|@prisma\/client|typeorm|knex|drizzle-orm)['"]/;
const MONGO_IMPORT = /(?:from|require\s*\(\s*)['"](?:mongodb|mongoose)['"]/;

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

function isPascalModel(name: string): boolean {
  return /^[A-Z][A-Za-z0-9]*$/.test(name);
}

function isCollectionName(name: string): boolean {
  return /^(collection|col)$/i.test(name) || /Collection$/i.test(name);
}

/** True only for MongoDB / mongoose receivers. Never Sequelize, Prisma, TypeORM, Knex, Drizzle, or unknown. */
function isMongoReceiver(node: AstNode, source: string): boolean {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') return false;
  const fileHasMongo = MONGO_IMPORT.test(source);
  const fileHasSqlOrm = SQL_ORM_IMPORT.test(source) && !fileHasMongo;
  if (fileHasSqlOrm) return false;

  const obj = node.callee.object;
  if (obj.type === 'Identifier') {
    if (isCollectionName(obj.name)) return true;
    if (isPascalModel(obj.name)) {
      if (/extends\s+BaseEntity\b/.test(source)) return false;
      return !fileHasSqlOrm;
    }
    return fileHasMongo;
  }
  if (obj.type === 'MemberExpression') {
    const prop = propName(obj);
    if (prop !== undefined && (prop === 'collection' || isCollectionName(prop))) return true;
    if (prop !== undefined && isPascalModel(prop)) return fileHasMongo;
    if (obj.object.type === 'Identifier' && obj.object.name === 'mongoose') return true;
  }
  return fileHasMongo;
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
  if (isValidatedRouteField(node)) return true;
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
          if (!MONGO_IMPORT.test(ctx.source) && !isMongoReceiver(node, ctx.source)) return;
          const expr = node.arguments[0];
          if (expr !== undefined && expr.type !== 'SpreadElement' && ctx.isTainted(expr)) {
            ctx.report({
              node,
              message: 'Tainted input is passed to mongoose $where (server-side JS).',
            });
          }
          return;
        }
        if (name !== undefined && SQL_ONLY_METHODS.has(name)) return;
        if (name === undefined || !MONGO_SINKS.has(name)) return;
        if (!isMongoReceiver(node, ctx.source)) return;
        const filter = node.arguments[0];
        if (filter === undefined || filter.type === 'SpreadElement') return;
        if (objectHasKey(filter, 'where')) return;
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
        if (ctx.holdsBuiltFilter(filter)) {
          ctx.report({
            node,
            message: 'A Mongo filter built from request input is passed to the query.',
            confidence: 'medium',
          });
          return;
        }
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
