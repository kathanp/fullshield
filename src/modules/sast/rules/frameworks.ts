import { calleeName, walk } from '../ast.js';
import type { AstNode, SastRule } from '../types.js';

const ROUTE_NAMES = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
const SINKS = new Set(['query', 'exec', 'execute', 'update', 'create', 'delete']);

function textOf(source: string, node: AstNode): string {
  const range = node.range;
  if (range === undefined) {return '';}
  return source.slice(range[0], range[1]);
}

function hasAuth(source: string): boolean {
  return /auth\s*\(|getServerSession|currentUser|UseGuards/.test(source);
}

function sinkUses(node: AstNode, source: string, needle: string): boolean {
  let hit = false;
  walk(node, (current) => {
    if (current.type !== 'CallExpression') {return;}
    const name = calleeName(current);
    if (name === undefined || !SINKS.has(name)) {return;}
    if (textOf(source, current).includes(needle)) {hit = true;}
  });
  return hit;
}

function decoratorName(expression: AstNode): string | undefined {
  if (expression.type === 'Identifier') {return expression.name;}
  if (expression.type === 'CallExpression') {return calleeName(expression);}
  return undefined;
}

function pipeSanitized(expression: AstNode): boolean {
  if (expression.type !== 'CallExpression') {return false;}
  return expression.arguments.some((arg) => {
    if (arg.type === 'Identifier') {return arg.name.endsWith('Pipe');}
    if (arg.type === 'NewExpression') {
      const name = calleeName(arg);
      return name !== undefined && name.endsWith('Pipe');
    }
    return false;
  });
}

export const nextRouteRule: SastRule = {
  meta: {
    id: 'SAST-NEXT-ROUTE-001',
    title: 'Next.js route handler reaches a data sink without an auth check',
    severity: 'medium',
    cwe: 'CWE-306',
    docs: 'https://nextjs.org/docs/app/building-your-application/routing/route-handlers',
  },
  create(ctx) {
    if (hasAuth(ctx.source)) {return {};}
    return {
      FunctionDeclaration(node) {
        if (node.type !== 'FunctionDeclaration' || node.id === null) {return;}
        if (!ROUTE_NAMES.has(node.id.name)) {return;}
        const parent = (node as AstNode & { parent?: AstNode }).parent;
        if (parent?.type !== 'ExportNamedDeclaration') {return;}
        if (!sinkUses(node, ctx.source, 'request') && !sinkUses(node, ctx.source, 'q')) {return;}
        ctx.report({
          node,
          message: 'A Next.js route handler reaches a data sink and does not call auth.',
          confidence: 'low',
        });
      },
    };
  },
};

export const nestBodyRule: SastRule = {
  meta: {
    id: 'SAST-NEST-001',
    title: 'NestJS body or query reaches a data sink without a guard or pipe',
    severity: 'high',
    cwe: 'CWE-89',
    docs: 'https://docs.nestjs.com/techniques/validation',
  },
  create(ctx) {
    if (/UseGuards/.test(ctx.source)) {return {};}
    return {
      MethodDefinition(node) {
        if (node.type !== 'MethodDefinition' || node.value.type !== 'FunctionExpression') {return;}
        for (const param of node.value.params) {
          const decorators = 'decorators' in param ? param.decorators : undefined;
          if (!Array.isArray(decorators)) {continue;}
          const names = decorators.map((item) => decoratorName(item.expression));
          const body = names.some((name) => name === 'Body' || name === 'Query' || name === 'Param');
          if (!body) {continue;}
          if (decorators.some((item) => pipeSanitized(item.expression))) {continue;}
          const paramName = param.type === 'Identifier' ? param.name : undefined;
          if (paramName === undefined) {continue;}
          if (!sinkUses(node.value, ctx.source, paramName)) {continue;}
          ctx.report({
            node,
            message: 'A NestJS body, query, or param reaches a data sink without a guard or pipe.',
          });
        }
      },
    };
  },
};

function schemaOnRoute(node: AstNode): boolean {
  if (node.type !== 'CallExpression') {return false;}
  return node.arguments.some((arg) => {
    if (arg.type !== 'ObjectExpression') {return false;}
    return arg.properties.some((prop) => prop.type === 'Property' && prop.key.type === 'Identifier' && prop.key.name === 'schema');
  });
}

export const fastifySchemaRule: SastRule = {
  meta: {
    id: 'SAST-FASTIFY-001',
    title: 'Fastify request body reaches a data sink without a schema',
    severity: 'high',
    cwe: 'CWE-89',
    docs: 'https://fastify.dev/docs/Reference/Validation-and-Serialization/',
  },
  create(ctx) {
    if (!/fastify/.test(ctx.source)) {return {};}
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name !== 'post' && name !== 'put' && name !== 'get' && name !== 'delete' && name !== 'patch') {return;}
        if (schemaOnRoute(node)) {return;}
        const handler = node.arguments.find((arg) => arg.type === 'ArrowFunctionExpression' || arg.type === 'FunctionExpression');
        if (handler === undefined) {return;}
        if (!sinkUses(handler, ctx.source, 'request.body') && !sinkUses(handler, ctx.source, 'request.query')) {return;}
        ctx.report({
          node,
          message: 'A Fastify route passes request.body or request.query to a data sink and does not set schema.',
        });
      },
    };
  },
};
