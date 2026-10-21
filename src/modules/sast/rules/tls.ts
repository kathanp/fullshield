import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { makeFindingId, type Finding } from '../../../core/finding.js';
import { propName, type NodeWithParent } from '../ast.js';
import type { AstNode, SastRule } from '../types.js';

const DOCS = 'https://cwe.mitre.org/data/definitions/295.html';
const REMEDIATION =
  'Turn TLS verification back on. Do not ship rejectUnauthorized: false or NODE_TLS_REJECT_UNAUTHORIZED=0.';

type TlsSeverity = { severity: 'high' | 'medium' | 'low'; context?: 'test' };

export function tlsTestPath(filename: string): boolean {
  const path = filename.replace(/\\/g, '/');
  if (/(^|\/)(test|__tests__)(\/|$)/.test(path)) {return true;}
  if (/\.(test|spec)\.[cm]?[jt]sx?$/.test(path)) {return true;}
  if (/(^|\/)scripts\/dev/.test(path)) {return true;}
  return false;
}

function isFalseLiteral(node: AstNode | undefined): boolean {
  return node?.type === 'Literal' && node.value === false;
}

function isZeroLiteral(node: AstNode | undefined): boolean {
  return node?.type === 'Literal' && (node.value === '0' || node.value === 0);
}

function propertyName(prop: TSESTree.Property): string | undefined {
  if (prop.computed) {return undefined;}
  if (prop.key.type === 'Identifier') {return prop.key.name;}
  if (prop.key.type === 'Literal' && typeof prop.key.value === 'string') {return prop.key.value;}
  return undefined;
}

function objectHasCa(obj: TSESTree.ObjectExpression): boolean {
  return obj.properties.some((prop) => prop.type === 'Property' && propertyName(prop) === 'ca');
}

function returnsUndefined(node: AstNode): boolean {
  if (node.type === 'ArrowFunctionExpression') {
    if (node.body.type !== 'BlockStatement') {
      return node.body.type === 'Identifier' && node.body.name === 'undefined';
    }
    return blockReturnsUndefined(node.body);
  }
  if (node.type === 'FunctionExpression') {return blockReturnsUndefined(node.body);}
  return false;
}

function blockReturnsUndefined(body: TSESTree.BlockStatement): boolean {
  return body.body.some(
    (stmt) =>
      stmt.type === 'ReturnStatement' &&
      stmt.argument?.type === 'Identifier' &&
      stmt.argument.name === 'undefined',
  );
}

/** Bad TLS option on this object, unless `ca` is set on the same object. */
function badOption(obj: TSESTree.ObjectExpression): AstNode | undefined {
  if (objectHasCa(obj)) {return undefined;}
  for (const prop of obj.properties) {
    if (prop.type !== 'Property') {continue;}
    const name = propertyName(prop);
    if (name === 'rejectUnauthorized' && isFalseLiteral(prop.value)) {return prop;}
    if (name === 'checkServerIdentity' && returnsUndefined(prop.value)) {return prop;}
    if (
      (name === 'connect' || name === 'https' || name === 'ssl' || name === 'tls' || name === 'httpsAgent') &&
      prop.value.type === 'ObjectExpression'
    ) {
      const nested = badOption(prop.value);
      if (nested !== undefined) {return nested;}
    }
  }
  return undefined;
}

function isTlsSink(node: TSESTree.CallExpression | TSESTree.NewExpression): boolean {
  const callee = node.callee;
  if (callee.type === 'Identifier') {return callee.name === 'got' || callee.name === 'Agent';}
  if (callee.type !== 'MemberExpression') {return false;}
  const prop = propName(callee);
  const object = callee.object.type === 'Identifier' ? callee.object.name : undefined;
  if (object === 'https' && (prop === 'request' || prop === 'get' || prop === 'Agent')) {return true;}
  if (object === 'tls' && prop === 'connect') {return true;}
  if (object === 'axios') {return true;}
  if (prop === 'Agent') {return true;}
  return false;
}

function memberIsEnv(node: AstNode, name: string): boolean {
  if (node.type !== 'MemberExpression') {return false;}
  if (propName(node) !== name && !(node.property.type === 'Literal' && node.property.value === name)) {return false;}
  const object = node.object;
  if (object.type !== 'MemberExpression') {return false;}
  return propName(object) === 'env' && object.object.type === 'Identifier' && object.object.name === 'process';
}

function devEnvGuard(node: AstNode): boolean {
  let current: AstNode | undefined = node;
  for (let i = 0; i < 40 && current !== undefined; i += 1) {
    const parent: AstNode | undefined = (current as unknown as NodeWithParent).parent;
    if (parent?.type === 'IfStatement' && ifTestIsDev(parent.test)) {return true;}
    current = parent;
  }
  return false;
}

function ifTestIsDev(test: AstNode): boolean {
  if (test.type !== 'BinaryExpression') {return false;}
  if (test.operator !== '!==' && test.operator !== '!=') {return false;}
  const env = memberIsEnv(test.left, 'NODE_ENV') ? test.left : memberIsEnv(test.right, 'NODE_ENV') ? test.right : undefined;
  const other = env === test.left ? test.right : test.left;
  return env !== undefined && other.type === 'Literal' && other.value === 'production';
}

function adjusted(filename: string, node: AstNode): TlsSeverity {
  if (tlsTestPath(filename)) {return { severity: 'low', context: 'test' };}
  if (devEnvGuard(node)) {return { severity: 'medium' };}
  return { severity: 'high' };
}

const tlsOptionRule: SastRule = {
  meta: {
    id: 'SAST-TLS-001',
    title: 'TLS certificate verification disabled',
    severity: 'high',
    cwe: 'CWE-295',
    docs: DOCS,
  },
  create(ctx) {
    const reportBad = (node: AstNode, message: string): void => {
      const level = adjusted(ctx.filename, node);
      ctx.report({ node, message, severity: level.severity, context: level.context });
    };
    return {
      'CallExpression'(node) {
        if (node.type !== 'CallExpression' && node.type !== 'NewExpression') {return;}
        if (!isTlsSink(node)) {return;}
        for (const arg of node.arguments) {
          if (arg.type !== 'ObjectExpression') {continue;}
          const hit = badOption(arg);
          if (hit !== undefined) {
            reportBad(hit, 'TLS verification is disabled for this connection.');
          }
        }
      },
      'NewExpression'(node) {
        if (node.type !== 'NewExpression') {return;}
        if (!isTlsSink(node)) {return;}
        for (const arg of node.arguments) {
          if (arg.type !== 'ObjectExpression') {continue;}
          const hit = badOption(arg);
          if (hit !== undefined) {
            reportBad(hit, 'TLS verification is disabled for this connection.');
          }
        }
      },
    };
  },
};

const tlsEnvRule: SastRule = {
  meta: {
    id: 'SAST-TLS-002',
    title: 'NODE_TLS_REJECT_UNAUTHORIZED disabled',
    severity: 'high',
    cwe: 'CWE-295',
    docs: DOCS,
  },
  create(ctx) {
    return {
      AssignmentExpression(node) {
        if (node.type !== 'AssignmentExpression') {return;}
        if (!memberIsEnv(node.left, 'NODE_TLS_REJECT_UNAUTHORIZED') || !isZeroLiteral(node.right)) {return;}
        const level = adjusted(ctx.filename, node);
        ctx.report({
          node,
          message: 'NODE_TLS_REJECT_UNAUTHORIZED is set to 0, which disables TLS verification.',
          severity: level.severity,
          context: level.context,
        });
      },
    };
  },
};

export const tlsRules: readonly SastRule[] = [tlsOptionRule, tlsEnvRule];

const ZERO_ASSIGN = /NODE_TLS_REJECT_UNAUTHORIZED(?:\s*[:=]\s*|\s+)\s*['"]?0['"]?(?!\d)/;

function configFile(filename: string): boolean {
  const base = filename.split('/').pop() ?? filename;
  if (base === 'Dockerfile' || base.startsWith('Dockerfile.') || base.endsWith('.dockerfile')) {return true;}
  if (base === 'package.json') {return true;}
  if (/^(docker-)?compose\.(ya?ml)$/.test(base)) {return true;}
  if (/^\.env(\..+)?$/.test(base)) {return true;}
  return false;
}

/** Dockerfile, package.json scripts, compose, and .env files. Source files use the AST rules. */
export function scanTlsConfigText(filename: string, source: string): Finding[] {
  if (!configFile(filename)) {return [];}
  const lines = source.split(/\r?\n/);
  const findings: Finding[] = [];
  lines.forEach((line, index) => {
    if (!ZERO_ASSIGN.test(line)) {return;}
    if (filename.endsWith('package.json') && !/"scripts"/.test(source)) {return;}
    const level = tlsTestPath(filename) ? { severity: 'low' as const, context: 'test' as const } : { severity: 'high' as const };
    const snippet = line.trim().slice(0, 120);
    findings.push({
      id: makeFindingId('SAST-TLS-002', filename, `${index + 1}|${snippet}`),
      ruleId: 'SAST-TLS-002',
      module: 'sast',
      title: 'NODE_TLS_REJECT_UNAUTHORIZED disabled',
      severity: level.severity,
      confidence: 'high',
      cwe: 'CWE-295',
      file: filename,
      line: index + 1,
      snippet,
      message: 'NODE_TLS_REJECT_UNAUTHORIZED is set to 0, which disables TLS verification.',
      remediation: REMEDIATION,
      references: [DOCS, 'CWE-295'],
      ...(level.context !== undefined ? { context: level.context } : {}),
    });
  });
  return findings;
}
