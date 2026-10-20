import { calleeName, isFunctionNode, propName, walk } from './ast.js';
import type { AstNode } from './types.js';

const PRIMITIVE = new Set(['string', 'number', 'boolean', 'IsString', 'IsNumber', 'IsInt', 'IsBoolean']);
const OPEN = new Set(['any', 'unknown', 'object', 'array', 'record', 'lazy', 'union', 'tuple']);
const SCHEMA_ROOT = new Set(['z', 'zod', 'Joi', 'joi']);
const ROUTE_METHODS = new Set(['post', 'put', 'patch', 'delete']);

type WithParent = AstNode & { parent?: AstNode; decorators?: AstNode[] };

function validationEnabled(): boolean {
  return process.env.FULLSHIELD_EXPERIMENTAL_VALIDATION === '1';
}

function parentOf(node: AstNode): AstNode | undefined {
  return (node as WithParent).parent;
}

function mentions(node: AstNode, names: ReadonlySet<string>): boolean {
  let current: AstNode | undefined = node;
  for (let i = 0; i < 12 && current !== undefined; i += 1) {
    if (current.type === 'CallExpression') {
      const name = calleeName(current);
      if (name !== undefined && names.has(name)) {return true;}
      current = current.callee.type === 'MemberExpression' ? current.callee.object : undefined;
      continue;
    }
    if (current.type === 'MemberExpression') {
      const name = propName(current);
      if (name !== undefined && names.has(name)) {return true;}
      current = current.object;
      continue;
    }
    if (current.type === 'Identifier' && names.has(current.name)) {return true;}
    break;
  }
  return false;
}

function rootName(node: AstNode): string | undefined {
  let current: AstNode | undefined = node;
  for (let i = 0; i < 8 && current !== undefined; i += 1) {
    if (current.type === 'Identifier') {return current.name;}
    if (current.type === 'CallExpression') {
      current = current.callee;
      continue;
    }
    if (current.type === 'MemberExpression') {
      current = current.object;
      continue;
    }
    break;
  }
  return undefined;
}

function propertyName(prop: AstNode): string | undefined {
  if (prop.type !== 'Property') {return undefined;}
  const key = prop.key;
  if (key.type === 'Identifier') {return key.name;}
  if (key.type === 'Literal' && typeof key.value === 'string') {return key.value;}
  return undefined;
}

function fieldsOfObjectSchema(node: AstNode): Set<string> {
  if (node.type !== 'CallExpression' || calleeName(node) !== 'object') {return new Set();}
  const root = rootName(node.callee);
  if (root === undefined || !SCHEMA_ROOT.has(root)) {return new Set();}
  const arg = node.arguments[0];
  if (arg === undefined || arg.type !== 'ObjectExpression') {return new Set();}
  const fields = new Set<string>();
  for (const prop of arg.properties) {
    if (prop.type !== 'Property') {continue;}
    const name = propertyName(prop);
    if (name === undefined) {continue;}
    if (mentions(prop.value, OPEN)) {continue;}
    if (mentions(prop.value, PRIMITIVE)) {fields.add(name);}
  }
  return fields;
}

function decoratorName(decorator: AstNode): string | undefined {
  const expr = decorator.type === 'Decorator' ? decorator.expression : decorator;
  if (expr === undefined) {return undefined;}
  if (expr.type === 'CallExpression') {return calleeName(expr);}
  if (expr.type === 'Identifier') {return expr.name;}
  return undefined;
}

function fieldsOfClass(node: AstNode): Set<string> {
  if (node.type !== 'ClassDeclaration' && node.type !== 'ClassExpression') {return new Set();}
  if (node.body.type !== 'ClassBody') {return new Set();}
  const fields = new Set<string>();
  for (const element of node.body.body) {
    if (element.type !== 'PropertyDefinition') {continue;}
    const key = element.key;
    const name = key.type === 'Identifier' ? key.name : undefined;
    if (name === undefined) {continue;}
    const decorators = (element as WithParent).decorators ?? [];
    if (decorators.some((decorator) => PRIMITIVE.has(decoratorName(decorator) ?? ''))) {fields.add(name);}
  }
  return fields;
}

function programOf(node: AstNode): AstNode | undefined {
  let current: AstNode | undefined = node;
  while (current !== undefined && current.type !== 'Program') {current = parentOf(current);}
  return current;
}

function bindings(program: AstNode): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  walk(program, (node) => {
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init !== null && node.init !== undefined) {
      const fields = fieldsOfObjectSchema(node.init);
      if (fields.size > 0) {map.set(node.id.name, fields);}
    }
    if (node.type === 'ClassDeclaration' && node.id !== null) {
      const fields = fieldsOfClass(node);
      if (fields.size > 0) {map.set(node.id.name, fields);}
    }
  });
  return map;
}

const bindingCache = new WeakMap<AstNode, Map<string, Set<string>>>();

function fieldsOfExpr(expr: AstNode, known: Map<string, Set<string>>): Set<string> {
  if (expr.type === 'Identifier') {return new Set(known.get(expr.name) ?? []);}
  if (expr.type === 'ClassExpression' || expr.type === 'ClassDeclaration') {return fieldsOfClass(expr);}
  const direct = fieldsOfObjectSchema(expr);
  if (expr.type !== 'CallExpression') {return direct;}
  for (const arg of expr.arguments) {
    if (arg.type === 'SpreadElement') {continue;}
    for (const name of fieldsOfExpr(arg, known)) {direct.add(name);}
  }
  return direct;
}

function isRouteCall(node: AstNode): boolean {
  if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {return false;}
  const method = propName(node.callee);
  if (method === undefined || !ROUTE_METHODS.has(method)) {return false;}
  return node.callee.object.type === 'Identifier' && /^(app|router)$/i.test(node.callee.object.name);
}

function routeOf(node: AstNode): AstNode | undefined {
  let current: AstNode | undefined = node;
  while (current !== undefined) {
    const parent = parentOf(current);
    if (isFunctionNode(current) && parent !== undefined && isRouteCall(parent)) {return parent;}
    current = parent;
  }
  return undefined;
}

function requestField(node: AstNode): string | undefined {
  if (node.type !== 'MemberExpression' || node.computed === true) {return undefined;}
  const field = node.property.type === 'Identifier' ? node.property.name : undefined;
  if (field === undefined || node.object.type !== 'MemberExpression' || node.object.computed === true) {return undefined;}
  const bag = node.object.property.type === 'Identifier' ? node.object.property.name : undefined;
  if (bag !== 'body' && bag !== 'query' && bag !== 'params') {return undefined;}
  if (node.object.object.type !== 'Identifier' || node.object.object.name !== 'req') {return undefined;}
  return field;
}

const routeCache = new WeakMap<AstNode, Set<string>>();

function fieldsForRoute(route: AstNode): Set<string> {
  const cached = routeCache.get(route);
  if (cached !== undefined) {return cached;}
  const program = programOf(route);
  const known = program === undefined ? new Map<string, Set<string>>() : (bindingCache.get(program) ?? bindings(program));
  if (program !== undefined) {bindingCache.set(program, known);}
  const fields = new Set<string>();
  if (route.type === 'CallExpression') {
    for (const arg of route.arguments) {
      if (arg.type === 'SpreadElement' || isFunctionNode(arg)) {continue;}
      for (const name of fieldsOfExpr(arg, known)) {fields.add(name);}
    }
  }
  routeCache.set(route, fields);
  return fields;
}

/** A request field forced to string, number, or boolean by a schema on this route. */
export function isValidatedRouteField(node: AstNode): boolean {
  if (!validationEnabled()) {return false;}
  const field = requestField(node);
  if (field === undefined) {return false;}
  const route = routeOf(node);
  if (route === undefined) {return false;}
  return fieldsForRoute(route).has(field);
}
