import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { calleeName, literalString, propName } from '../ast.js';
import type { AstNode, SastRule } from '../types.js';
import { tlsTestPath } from './tls.js';

const DOCS = 'https://cwe.mitre.org/data/definitions/327.html';

function level(filename: string): { severity?: 'low'; context?: 'test' } {
  if (!tlsTestPath(filename)) {return {};}
  return { severity: 'low', context: 'test' };
}

function propertyName(prop: TSESTree.Property): string | undefined {
  if (prop.computed) {return undefined;}
  if (prop.key.type === 'Identifier') {return prop.key.name;}
  if (prop.key.type === 'Literal' && typeof prop.key.value === 'string') {return prop.key.value;}
  return undefined;
}

function propNumber(obj: TSESTree.ObjectExpression, name: string): number | undefined {
  for (const prop of obj.properties) {
    if (prop.type !== 'Property' || propertyName(prop) !== name) {continue;}
    if (prop.value.type === 'Literal' && typeof prop.value.value === 'number') {return prop.value.value;}
  }
  return undefined;
}

function propString(obj: TSESTree.ObjectExpression, name: string): string | undefined {
  for (const prop of obj.properties) {
    if (prop.type !== 'Property' || propertyName(prop) !== name) {continue;}
    return literalString(prop.value);
  }
  return undefined;
}

function hasProp(obj: TSESTree.ObjectExpression, name: string): boolean {
  return obj.properties.some((prop) => prop.type === 'Property' && propertyName(prop) === name);
}

/** String literal, Buffer.from(literal), or Buffer.alloc(n). randomBytes is not a literal. */
function weakIv(node: AstNode | undefined): boolean {
  if (node === undefined || node.type === 'SpreadElement') {return false;}
  if (node.type === 'Literal' && typeof node.value === 'string') {return true;}
  if (node.type !== 'CallExpression') {return false;}
  const name = calleeName(node);
  if (name === 'alloc' && node.callee.type === 'MemberExpression') {
    const object = node.callee.object;
    return object.type === 'Identifier' && object.name === 'Buffer';
  }
  if (name === 'from' && node.callee.type === 'MemberExpression') {
    const object = node.callee.object;
    return object.type === 'Identifier' && object.name === 'Buffer' && literalString(node.arguments[0]) !== undefined;
  }
  return false;
}

function stringLiteral(node: AstNode | undefined): string | undefined {
  if (node === undefined || node.type === 'SpreadElement') {return undefined;}
  return literalString(node);
}

export const cipherRule: SastRule = {
  meta: {
    id: 'SAST-CIPHER-001',
    title: 'Weak cipher mode or IV',
    severity: 'high',
    cwe: 'CWE-327',
    docs: DOCS,
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name === 'createCipher' || name === 'createDecipher') {
          const extra = level(ctx.filename);
          ctx.report({
            node,
            message: `${name} is deprecated and does not take an IV.`,
            ...extra,
          });
          return;
        }
        if (name !== 'createCipheriv') {return;}
        const algo = stringLiteral(node.arguments[0]);
        const iv = node.arguments[2];
        const ecb = algo !== undefined && /-ecb$/i.test(algo);
        const badIv = weakIv(iv);
        if (!ecb && !badIv) {return;}
        const extra = level(ctx.filename);
        ctx.report({
          node,
          message: ecb ? `Cipher ${algo} uses ECB.` : 'The IV is a literal or an all-zero Buffer.alloc.',
          ...extra,
        });
      },
    };
  },
};

export const cipherKeyRule: SastRule = {
  meta: {
    id: 'SAST-CIPHER-002',
    title: 'Hardcoded symmetric key',
    severity: 'high',
    cwe: 'CWE-321',
    docs: 'https://cwe.mitre.org/data/definitions/321.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') {return;}
        const name = calleeName(node);
        if (name !== 'createCipheriv' && name !== 'createHmac') {return;}
        const key = stringLiteral(node.arguments[1]);
        if (key === undefined) {return;}
        const extra = level(ctx.filename);
        ctx.report({ node, message: `${name} is called with a string-literal key.`, ...extra });
      },
    };
  },
};

export const rsaRule: SastRule = {
  meta: {
    id: 'SAST-RSA-001',
    title: 'Weak key generation',
    severity: 'medium',
    cwe: 'CWE-326',
    docs: 'https://cwe.mitre.org/data/definitions/326.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression' || calleeName(node) !== 'generateKeyPair') {return;}
        const kind = stringLiteral(node.arguments[0]);
        const options = node.arguments[1];
        if (options?.type !== 'ObjectExpression') {return;}
        const bits = kind === 'rsa' ? propNumber(options, 'modulusLength') : undefined;
        const curve = kind === 'ec' ? propString(options, 'namedCurve') : undefined;
        if (bits === undefined && curve === undefined) {return;}
        if (bits !== undefined && bits >= 2048) {return;}
        if (curve !== undefined && !curve.startsWith('secp192')) {return;}
        const extra = level(ctx.filename);
        ctx.report({
          node,
          message: bits !== undefined ? `RSA modulusLength ${bits} is below 2048.` : `Curve ${curve} is too small.`,
          severity: extra.severity ?? 'medium',
          context: extra.context,
        });
      },
    };
  },
};

export const jwtExpiryRule: SastRule = {
  meta: {
    id: 'SAST-JWT-002',
    title: 'JWT without expiry or with a short HMAC secret',
    severity: 'medium',
    cwe: 'CWE-613',
    docs: 'https://cwe.mitre.org/data/definitions/613.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression' || calleeName(node) !== 'sign') {return;}
        const object = node.callee.type === 'MemberExpression' ? node.callee.object : undefined;
        const owner = object?.type === 'Identifier' ? object.name : object?.type === 'MemberExpression' ? propName(object) : undefined;
        if (owner !== 'jwt') {return;}
        const secret = stringLiteral(node.arguments[1]);
        const payload = node.arguments[0];
        const options = node.arguments[2];
        const expires = options?.type === 'ObjectExpression' && hasProp(options, 'expiresIn');
        const exp = payload?.type === 'ObjectExpression' && hasProp(payload, 'exp');
        const extra = level(ctx.filename);
        if (!expires && !exp) {
          ctx.report({
            node,
            message: 'jwt.sign has no expiresIn or exp.',
            severity: extra.severity ?? 'medium',
            context: extra.context,
          });
        }
        if (secret !== undefined && Buffer.byteLength(secret) < 32) {
          ctx.report({
            node,
            message: 'jwt.sign HMAC secret literal is shorter than 32 bytes.',
            severity: extra.severity ?? 'medium',
            context: extra.context,
          });
        }
      },
    };
  },
};

export const crypto2Rules: readonly SastRule[] = [cipherRule, cipherKeyRule, rsaRule, jwtExpiryRule];
