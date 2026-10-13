import { calleeName } from '../ast.js';
import type { SastRule } from '../types.js';

const PATH_SINKS = new Set([
  'sendFile',
  'readFile',
  'readFileSync',
  'writeFile',
  'writeFileSync',
  'appendFile',
  'appendFileSync',
  'unlink',
  'unlinkSync',
  'createReadStream',
  'createWriteStream',
  'open',
  'openSync',
  'access',
  'stat',
  'statSync',
  'lstat',
  'realpath',
  'rm',
  'rmSync',
  'rmdir',
  'mkdir',
  'readdir',
  'copyFile',
  'rename',
  'chmod',
]);

export const pathRule: SastRule = {
  meta: {
    id: 'SAST-PATH-001',
    title: 'Path traversal via unsanitized file path',
    severity: 'high',
    cwe: 'CWE-22',
    docs: 'https://cwe.mitre.org/data/definitions/22.html',
  },
  create(ctx) {
    return {
      CallExpression(node) {
        if (node.type !== 'CallExpression') return;
        const name = calleeName(node);
        if (name === undefined || !PATH_SINKS.has(name)) return;
        const pathArg = node.arguments[0];
        if (pathArg === undefined || pathArg.type === 'SpreadElement') return;
        if (!ctx.isTainted(pathArg)) return;
        if (ctx.isPathSanitized(pathArg)) return;
        ctx.report({
          node,
          message: 'Tainted input is used as a file path without path.resolve + prefix check.',
        });
      },
    };
  },
};
