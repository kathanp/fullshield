import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { parsePoolEnabled, parseWithPool } from './parse-pool.js';
import type { AstNode } from '../modules/sast/types.js';

const SOURCE_EXT = /\.[cm]?[jt]sx?$/;

interface CacheEntry {
  ast: AstNode | undefined;
}

let session:
  | { cache: Map<string, CacheEntry>; pending: Map<string, Promise<AstNode | undefined>>; counts: Map<string, number> }
  | undefined;
let lastCounts = new Map<string, number>();

export function sharedAstActive(): boolean {
  return session !== undefined;
}

export function beginSharedAst(): void {
  session = { cache: new Map(), pending: new Map(), counts: new Map() };
  lastCounts = new Map();
}

export function endSharedAst(): void {
  lastCounts = new Map(session?.counts ?? []);
  session = undefined;
}

/** Parser invocations in the scan that just finished. One per source file. */
export function lastParseCounts(): ReadonlyMap<string, number> {
  return lastCounts;
}

function cacheKey(file: string, source: string): string {
  return `${file}\0${createHash('sha256').update(source).digest('hex')}`;
}

function cloneAst(ast: AstNode | undefined): AstNode | undefined {
  if (ast === undefined) {return undefined;}
  try {
    return structuredClone(ast);
  } catch {
    return ast;
  }
}

async function parseFresh(source: string): Promise<AstNode | undefined> {
  if (parsePoolEnabled()) {
    try {
      const ast = (await parseWithPool([source]))[0];
      if (ast !== undefined && ast !== null && typeof ast === 'object') {return ast as AstNode;}
    } catch {
      // The in-process parser is the same fallback the SAST engine uses.
    }
  }
  try {
    const { parse } = await import('@typescript-eslint/typescript-estree');
    return parse(source, {
      loc: true,
      range: true,
      comment: false,
      jsx: true,
      errorOnUnknownASTType: false,
      errorOnTypeScriptSyntacticAndSemanticIssues: false,
    });
  } catch {
    return undefined;
  }
}

/** Parse this file once per scan. Later callers get a clone of that AST. */
export async function sharedParse(file: string, source: string): Promise<AstNode | undefined> {
  if (session === undefined) {return cloneAst(await parseFresh(source));}
  const key = cacheKey(file, source);
  const hit = session.cache.get(key);
  if (hit !== undefined) {return cloneAst(hit.ast);}
  const inflight = session.pending.get(key);
  if (inflight !== undefined) {return cloneAst(await inflight);}
  const current = session;
  const work = parseFresh(source).then((fresh) => {
    const ast = cloneAst(fresh);
    current.counts.set(file, (current.counts.get(file) ?? 0) + 1);
    current.cache.set(key, { ast });
    current.pending.delete(key);
    return ast;
  });
  current.pending.set(key, work);
  return cloneAst(await work);
}

/** Fill the scan cache before modules run. Targets the parser rows from the step 1 profile. */
export async function preparseProject(cwd: string, files: readonly string[], maxBytes: number): Promise<void> {
  for (const rel of files) {
    if (!SOURCE_EXT.test(rel)) {continue;}
    let source: string;
    try {
      source = await readFile(join(cwd, rel), 'utf8');
    } catch {
      continue;
    }
    if (source.includes('\u0000') || Buffer.byteLength(source) > maxBytes) {continue;}
    await sharedParse(rel, source);
  }
}
