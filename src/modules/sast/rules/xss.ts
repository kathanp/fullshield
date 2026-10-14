import { calleeName, literalString, walk } from '../ast.js';
import type { AstNode, RuleContext, SastRule } from '../types.js';

export const TEMPLATE_EXT = /\.(ejs|hbs|njk)$/;

function containsHtml(node: AstNode): boolean {
  let found = false;
  walk(node, (child) => {
    const lit = literalString(child);
    if (lit !== undefined && /<[^>]+>/.test(lit)) found = true;
    if (child.type === 'TemplateLiteral') {
      for (const q of child.quasis) {
        if (/<[^>]+>/.test(q.value.cooked ?? q.value.raw)) found = true;
      }
    }
  });
  return found;
}

function lineNode(line: number): AstNode {
  return {
    type: 'Literal',
    value: '',
    raw: "''",
    loc: { start: { line, column: 0 }, end: { line, column: 0 } },
    range: [0, 0],
  } as unknown as AstNode;
}

/** Unescaped template interpolations (`<%-` / `{{{`) that are not includes. */
function scanTemplateXss(ctx: RuleContext): void {
  if (!TEMPLATE_EXT.test(ctx.filename)) return;
  const lines = ctx.source.split(/\r?\n/);
  lines.forEach((line, index) => {
    const ejs = /<%-(?!\s*include\b)/g;
    const hbs = /\{\{\{(?!\/)/g;
    if (ejs.test(line) || hbs.test(line)) {
      ctx.report({
        node: lineNode(index + 1),
        message: 'Unescaped template interpolation (<%- or {{{) can produce XSS.',
      });
    }
  });
}

export const xssRule: SastRule = {
  meta: {
    id: 'SAST-XSS-001',
    title: 'Reflected XSS via HTML response',
    severity: 'high',
    cwe: 'CWE-79',
    docs: 'https://cwe.mitre.org/data/definitions/79.html',
  },
  create(ctx) {
    scanTemplateXss(ctx);
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') return;
        const name = calleeName(node);
        if (name !== 'send' && name !== 'write') return;
        const arg = node.arguments[0];
        if (arg === undefined || arg.type === 'SpreadElement') return;
        if (!ctx.isTainted(arg) || ctx.isSanitizedFor(arg, 'xss')) return;
        if (!containsHtml(arg) && !/\{\{\{/.test(ctx.source) && !/<%-/.test(ctx.source)) return;
        ctx.report({
          node,
          message: 'Tainted input is interpolated into an HTML response.',
        });
      },
    };
  },
};
