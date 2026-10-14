import { calleeName } from '../ast.js';
import type { SastRule } from '../types.js';

const SSRF_CALLEES = new Set(['fetch', 'request', 'get', 'post', 'put', 'patch', 'delete']);
const HTTP_LIBS = /^(axios|http|https|needle|got|request|superagent|undici)$/;

export const ssrfRule: SastRule = {
  meta: {
    id: 'SAST-SSRF-001',
    title: 'SSRF via tainted URL',
    severity: 'high',
    cwe: 'CWE-918',
    docs: 'https://cwe.mitre.org/data/definitions/918.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') return;
        const name = calleeName(node);
        if (name === undefined || !SSRF_CALLEES.has(name)) return;
        const isFetch = node.callee.type === 'Identifier' && node.callee.name === 'fetch';
        const isHttpLib =
          node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' &&
          HTTP_LIBS.test(node.callee.object.name);
        if (!isFetch && !isHttpLib) return;
        const url = node.arguments[0];
        if (url === undefined || url.type === 'SpreadElement') return;
        if (!ctx.isTainted(url) || ctx.isSanitizedFor(url, 'url')) return;
        ctx.report({
          node,
          message: 'Tainted URL is passed to fetch/axios/http.request.',
        });
      },
    };
  },
};
