import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { ResolvedConfig } from '../../core/config.js';
import { parseCacheDir } from '../../core/parse-pool.js';
import { packageVersion } from '../../core/version.js';
import {
  analyzeFunctionWithSeed,
  fileTaintSummary,
  type FunctionTaintSummary,
  type ScopeFacts,
} from './taint.js';
import type { AstNode } from './types.js';
import { classesEnabled, frameworksEnabled, sastGapsEnabled, taintV2Enabled } from './experimental.js';

export function taintSummariesEnabled(): boolean {
  return process.env.FULLSHIELD_TAINT_SUMMARIES === '1';
}

interface StoredFileSummary {
  v: 1;
  returnsTaint: string[];
  functions: FunctionTaintSummary[];
}

interface StoredFacts {
  v: 1;
  tainted: string[];
  pathSanitized: string[];
  sqlCleared: string[];
  urlSanitized: string[];
  xssSanitized: string[];
  nosqlSanitized: string[];
  requestObjects: string[];
  builtFilters: string[];
  filterReturners: string[];
  returners: string[];
  hasPasswordName: boolean;
}

let configHash = '';

export function setTaintSummaryConfig(config: ResolvedConfig | undefined): void {
  fileMemo.clear();
  if (config === undefined) {
    configHash = '';
    return;
  }
  configHash = createHash('sha256')
    .update(
      JSON.stringify({
        maxFileBytes: config.sast.maxFileBytes,
        sources: config.sast.sources ?? [],
        sanitizers: config.sast.sanitizers ?? [],
        taintV2: taintV2Enabled(),
        frameworks: frameworksEnabled(),
        gaps: sastGapsEnabled(),
        classes: classesEnabled(),
        custom: process.env.FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS === '1',
        ...(process.env.FULLSHIELD_EXPERIMENTAL_MODELS === '1' ? { models: true } : {}),
      }),
    )
    .digest('hex');
}

function summaryDir(): string {
  return process.env.FULLSHIELD_TAINT_SUMMARY_DIR ?? join(parseCacheDir(), 'taint');
}

export function taintSummaryKey(source: string, extra = ''): string {
  return createHash('sha256')
    .update(packageVersion())
    .update('\0')
    .update(configHash)
    .update('\0')
    .update(extra)
    .update('\0')
    .update(source)
    .digest('hex');
}

function summaryPath(key: string): string {
  return join(summaryDir(), `${key}.json`);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function readJson(key: string): unknown {
  let text: string;
  try {
    text = readFileSync(summaryPath(key), 'utf8');
  } catch {
    return undefined;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    discard(key);
    return undefined;
  }
}

function discard(key: string): void {
  rmSync(summaryPath(key), { force: true });
}

function writeJson(key: string, value: unknown): void {
  const dir = summaryDir();
  mkdirSync(dir, { recursive: true });
  writeFileSync(summaryPath(key), JSON.stringify(value));
}

function readFileSummary(key: string): StoredFileSummary | undefined {
  const raw = readJson(key);
  if (typeof raw !== 'object' || raw === null) {
    if (raw !== undefined) discard(key);
    return undefined;
  }
  const row = raw as Partial<StoredFileSummary>;
  if (row.v !== 1 || !isStringArray(row.returnsTaint) || !Array.isArray(row.functions)) {
    discard(key);
    return undefined;
  }
  return row as StoredFileSummary;
}

const fileMemo = new Map<string, StoredFileSummary>();

/** Returner names for this source. A hit skips the callee walk. A bad file is deleted. */
export function cachedReturners(source: string, ast: AstNode): Set<string> {
  const key = taintSummaryKey(source, 'file');
  const memo = fileMemo.get(key);
  if (memo !== undefined) return new Set(memo.returnsTaint);
  const cached = readFileSummary(key);
  if (cached !== undefined) {
    fileMemo.set(key, cached);
    return new Set(cached.returnsTaint);
  }
  const summary = fileTaintSummary(ast);
  const stored: StoredFileSummary = { v: 1, returnsTaint: summary.returnsTaint, functions: summary.functions };
  fileMemo.set(key, stored);
  writeJson(key, stored);
  return new Set(stored.returnsTaint);
}

function lists(facts: ScopeFacts): StoredFacts {
  const names = (set: Set<string>): string[] => [...set].sort();
  return {
    v: 1,
    tainted: names(facts.tainted),
    pathSanitized: names(facts.pathSanitized),
    sqlCleared: names(facts.sqlCleared),
    urlSanitized: names(facts.urlSanitized),
    xssSanitized: names(facts.xssSanitized),
    nosqlSanitized: names(facts.nosqlSanitized),
    requestObjects: names(facts.requestObjects),
    builtFilters: names(facts.builtFilters),
    filterReturners: names(facts.filterReturners),
    returners: names(facts.returners),
    hasPasswordName: facts.hasPasswordName,
  };
}

function factsFrom(row: StoredFacts): ScopeFacts {
  return {
    tainted: new Set(row.tainted),
    pathSanitized: new Set(row.pathSanitized),
    sqlCleared: new Set(row.sqlCleared),
    urlSanitized: new Set(row.urlSanitized),
    xssSanitized: new Set(row.xssSanitized),
    nosqlSanitized: new Set(row.nosqlSanitized),
    requestObjects: new Set(row.requestObjects),
    builtFilters: new Set(row.builtFilters),
    filterReturners: new Set(row.filterReturners),
    returners: new Set(row.returners),
    hasPasswordName: row.hasPasswordName,
  };
}

function readFacts(key: string): ScopeFacts | undefined {
  const raw = readJson(key);
  if (typeof raw !== 'object' || raw === null) {
    if (raw !== undefined) discard(key);
    return undefined;
  }
  const row = raw as Partial<StoredFacts>;
  if (
    row.v !== 1 ||
    !isStringArray(row.tainted) ||
    !isStringArray(row.pathSanitized) ||
    !isStringArray(row.sqlCleared) ||
    !isStringArray(row.urlSanitized) ||
    !isStringArray(row.xssSanitized) ||
    !isStringArray(row.nosqlSanitized) ||
    !isStringArray(row.requestObjects) ||
    !isStringArray(row.builtFilters) ||
    !isStringArray(row.filterReturners) ||
    !isStringArray(row.returners) ||
    typeof row.hasPasswordName !== 'boolean'
  ) {
    discard(key);
    return undefined;
  }
  return factsFrom(row as StoredFacts);
}

/** Same facts as a fresh seed walk. The callee body is not analyzed again on a hit. */
export function cachedFunctionFacts(fileSource: string, fn: AstNode, seed: readonly string[]): ScopeFacts {
  const key = taintSummaryKey(fileSource, `seed:${fn.loc?.start.line ?? 0}:${seed.join(',')}`);
  const cached = readFacts(key);
  if (cached !== undefined) return cached;
  const facts = analyzeFunctionWithSeed(fn, seed);
  writeJson(key, lists(facts));
  return facts;
}
