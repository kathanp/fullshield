import { configFinding } from './finding.js';
import { attachParents, calleeName, isFunctionNode, literalString, propName, walk } from '../sast/ast.js';
import type { AstNode } from '../sast/types.js';
import type { Finding } from '../../core/finding.js';

const ORIGIN = 'access-control-allow-origin';
const CREDS = 'access-control-allow-credentials';

interface CorsState {
  reflected?: AstNode;
  creds: boolean;
}

function isOriginMember(node: AstNode): boolean {
  if (node.type !== 'MemberExpression' || propName(node) !== 'origin') {return false;}
  const headers = node.object;
  return headers.type === 'MemberExpression' && propName(headers) === 'headers';
}

function scopeOf(node: AstNode): AstNode {
  let current: AstNode | undefined = node;
  while (current !== undefined) {
    if (isFunctionNode(current) || current.type === 'Program') {return current;}
    current = (current as { parent?: AstNode }).parent;
  }
  return node;
}

function owned(node: AstNode, scope: AstNode): boolean {
  return scopeOf(node) === scope;
}

function isReflected(node: AstNode, names: ReadonlySet<string>): boolean {
  if (isOriginMember(node)) {return true;}
  return node.type === 'Identifier' && names.has(node.name);
}

function credsValue(node: AstNode | undefined): boolean {
  return node?.type === 'Literal' && (node.value === true || node.value === 'true');
}

function propValue(node: AstNode, name: string): AstNode | undefined {
  if (node.type !== 'ObjectExpression') {return undefined;}
  for (const prop of node.properties) {
    if (prop.type !== 'Property') {continue;}
    const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
    if (key === name) {return prop.value;}
  }
  return undefined;
}

function headerKey(node: AstNode): string | undefined {
  const text = literalString(node);
  return text?.toLowerCase();
}

function noteCors(node: AstNode, names: ReadonlySet<string>, state: CorsState): void {
  if (node.type !== 'CallExpression') {return;}
  const options = node.arguments[0];
  if (options === undefined || options.type !== 'ObjectExpression') {return;}
  const origin = propValue(options, 'origin');
  if (credsValue(propValue(options, 'credentials')) && origin !== undefined && isReflected(origin, names)) {
    state.creds = true;
    state.reflected ??= origin;
  }
}

function notePair(key: string | undefined, value: AstNode | undefined, names: ReadonlySet<string>, state: CorsState): void {
  if (key === CREDS && credsValue(value)) {state.creds = true;}
  if (key === ORIGIN && value !== undefined && isReflected(value, names)) {
    state.reflected ??= value;
  }
}

function noteHeaders(node: AstNode, names: ReadonlySet<string>, state: CorsState): void {
  if (node.type !== 'CallExpression') {return;}
  const name = calleeName(node);
  if (name !== 'setHeader' && name !== 'header' && name !== 'set') {return;}
  const first = node.arguments[0];
  const second = node.arguments[1];
  if (first?.type === 'ObjectExpression') {
    for (const prop of first.properties) {
      if (prop.type !== 'Property') {continue;}
      const key = prop.key.type === 'Identifier' ? prop.key.name : literalString(prop.key);
      notePair(key?.toLowerCase(), prop.value, names, state);
    }
    return;
  }
  if (first !== undefined) {notePair(headerKey(first), second, names, state);}
}

function originNames(scope: AstNode): Set<string> {
  const names = new Set<string>();
  walk(scope, (node) => {
    if (!owned(node, scope)) {return;}
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init !== null && node.init !== undefined && isOriginMember(node.init)) {
      names.add(node.id.name);
    }
    if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier' && isOriginMember(node.right)) {
      names.add(node.left.name);
    }
  });
  return names;
}

function reflectIn(scope: AstNode): AstNode | undefined {
  const names = originNames(scope);
  const state: CorsState = { creds: false };
  walk(scope, (node) => {
    if (node.type !== 'CallExpression' || !owned(node, scope)) {return;}
    if (calleeName(node) === 'cors') {noteCors(node, names, state);}
    noteHeaders(node, names, state);
  });
  return state.creds ? state.reflected : undefined;
}

async function parseCors(source: string): Promise<AstNode> {
  const { parse } = await import('@typescript-eslint/typescript-estree');
  return parse(source, {
    loc: true,
    range: true,
    comment: false,
    jsx: true,
    errorOnUnknownASTType: false,
    errorOnTypeScriptSyntacticAndSemanticIssues: false,
  });
}

export async function scanCorsReflect(file: string, source: string): Promise<Finding[]> {
  let ast: AstNode;
  try {
    ast = await parseCors(source);
  } catch {
    return [];
  }
  attachParents(ast);
  const scopes: AstNode[] = [ast];
  walk(ast, (node) => {
    if (isFunctionNode(node)) {scopes.push(node);}
  });
  const findings: Finding[] = [];
  for (const scope of scopes) {
    const reflected = reflectIn(scope);
    if (reflected === undefined) {continue;}
    findings.push(
      configFinding(
        'CONFIG-CORS-002',
        'Reflected CORS origin with credentials',
        'high',
        file,
        'Access-Control-Allow-Origin is the request Origin header and credentials are allowed on that response.',
        'Use a fixed allow-list. Do not reflect the request Origin when credentials are allowed.',
        reflected.loc?.start.line,
      ),
    );
  }
  return findings;
}
