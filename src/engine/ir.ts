import { parse, type TSESTree } from '@typescript-eslint/typescript-estree';

import { irCacheKey, irConfigHash, readCachedIr, writeCachedIr } from './ir-cache.js';
import { irEnabled } from './ir-flag.js';
import { lowerAst } from './ir-lower.js';
import { queryModule } from './ir-query.js';
import type { IrQueryFinding, IrResolveContext, ModuleIr } from './ir-types.js';

export { irCacheKey, irConfigHash, readCachedIr, writeCachedIr } from './ir-cache.js';
export { irEnabled } from './ir-flag.js';
export type {
  FunctionIr,
  ImportLink,
  IrNode,
  IrOp,
  IrParam,
  IrQueryFinding,
  IrResolveContext,
  ModuleIr,
} from './ir-types.js';

/**
 * Lower `source` to SSA IR. This module is not on the scan path.
 * Flag off, `runIrQuery` returns no findings and the cache is not touched.
 *
 * Not modeled here: closure capture across functions, switch fallthrough,
 * and per-field heap slots (a tainted property store taints the object).
 */
export function lowerSource(source: string, file = 'inline.js', ctx?: IrResolveContext): ModuleIr {
  return lowerAst(file, parseIr(source), ctx);
}

/** Cache keyed by content, package version, and config. Corrupt entries are deleted. */
export function lowerSourceCached(source: string, file = 'inline.js', ctx?: IrResolveContext): ModuleIr {
  if (!irEnabled()) {return lowerSource(source, file, ctx);}
  const configHash = irConfigHash(file, ctx);
  const key = irCacheKey(source, configHash);
  const cached = readCachedIr(key, configHash);
  if (cached !== undefined) {return cached;}
  const ir = lowerSource(source, file, ctx);
  writeCachedIr(key, ir, configHash);
  return ir;
}

/**
 * Source → sink on the IR for `req.<query|body|params|headers|files>` flowing to `*.query(...)`.
 * Other SAST rules are not re-expressed. Requires FULLSHIELD_EXPERIMENTAL_IR=1.
 */
export function runIrQuery(source: string, file = 'inline.js'): IrQueryFinding[] {
  if (!irEnabled()) {return [];}
  return queryModule(lowerSource(source, file));
}

function parseIr(code: string): TSESTree.Program {
  return parse(code, {
    loc: true,
    range: true,
    comment: false,
    jsx: true,
    errorOnUnknownASTType: false,
    errorOnTypeScriptSyntacticAndSemanticIssues: false,
  });
}
