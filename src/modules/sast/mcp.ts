import { calleeName, propName } from './ast.js';
import { mcpCfgEnabled } from './experimental.js';
import type { AstNode } from './types.js';

/** True when `fn` is the callback of server.tool / registerTool / addTool. */
export function isMcpToolHandler(fn: AstNode): boolean {
  if (!mcpCfgEnabled()) return false;
  const parent = (fn as { parent?: AstNode }).parent;
  if (parent === undefined || parent.type !== 'CallExpression') return false;
  const name = calleeName(parent);
  if (name !== 'tool' && name !== 'registerTool' && name !== 'addTool') return false;
  const args = parent.arguments;
  return args[args.length - 1] === fn;
}

/** `request.params.arguments` — model-provided MCP tool args. */
export function isMcpArgsTaintSource(node: AstNode): boolean {
  if (!mcpCfgEnabled() || node.type !== 'MemberExpression') return false;
  if (propName(node) !== 'arguments') return false;
  const obj = node.object;
  return obj.type === 'MemberExpression' && propName(obj) === 'params';
}
