import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { parseCacheDir } from '../core/parse-pool.js';
import { packageVersion } from '../core/version.js';
import { irEnabled } from './ir-flag.js';
import type { FunctionIr, ImportLink, IrNode, IrParam, IrResolveContext, ModuleIr } from './ir-types.js';

const OPS = new Set([
  'assign',
  'call',
  'return',
  'phi',
  'property-load',
  'property-store',
  'await',
  'branch',
]);

interface IrCacheEnvelope {
  v: 1;
  configHash: string;
  ir: ModuleIr;
}

/** Directory under the parse cache, or `FULLSHIELD_IR_CACHE_DIR` when a test sets it. */
function irCacheDir(): string {
  const override = process.env.FULLSHIELD_IR_CACHE_DIR;
  if (override !== undefined && override.length > 0) {return override;}
  return join(parseCacheDir(), 'ir');
}

/** Content hash + package version + config hash. The config hash includes the file path. */
export function irCacheKey(source: string, configHash: string): string {
  return createHash('sha256')
    .update(packageVersion())
    .update('\0')
    .update(configHash)
    .update('\0')
    .update(source)
    .digest('hex');
}

export function irConfigHash(file: string, ctx?: IrResolveContext): string {
  const files = ctx?.files === undefined ? [] : [...ctx.files].sort(cmp);
  return createHash('sha256')
    .update(stableStringify({
      file,
      tsPaths: ctx?.tsPaths ?? null,
      files,
      packageExports: ctx?.packageExports ?? null,
    }))
    .digest('hex');
}

/**
 * Read one cache entry. A missing file is a miss.
 * Invalid JSON, a bad envelope, or a config-hash mismatch deletes the file.
 * Flag off does not read and does not delete.
 */
export function readCachedIr(key: string, configHash: string): ModuleIr | undefined {
  if (!irEnabled()) {return undefined;}
  const path = cacheFile(key);
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    discard(path);
    return undefined;
  }
  const ir = openEnvelope(raw, configHash);
  if (ir === undefined) {
    discard(path);
    return undefined;
  }
  return ir;
}

export function writeCachedIr(key: string, ir: ModuleIr, configHash: string): void {
  if (!irEnabled()) {return;}
  const path = cacheFile(key);
  mkdirSync(dirname(path), { recursive: true });
  const body: IrCacheEnvelope = { v: 1, configHash, ir };
  writeFileSync(path, JSON.stringify(body));
}

function cacheFile(key: string): string {
  if (!/^[a-f0-9]{64}$/.test(key)) {
    throw new TypeError('IR cache key must be a sha256 hex digest');
  }
  return join(irCacheDir(), `${key}.json`);
}

function discard(path: string): void {
  rmSync(path, { force: true });
}

function openEnvelope(raw: unknown, configHash: string): ModuleIr | undefined {
  if (!isRecord(raw) || raw.v !== 1 || typeof raw.configHash !== 'string') {return undefined;}
  if (raw.configHash !== configHash) {return undefined;}
  return isModuleIr(raw.ir) ? raw.ir : undefined;
}

function isModuleIr(value: unknown): value is ModuleIr {
  if (!isRecord(value) || typeof value.file !== 'string') {return false;}
  if (!Array.isArray(value.imports) || !value.imports.every(isImportLink)) {return false;}
  if (!Array.isArray(value.functions) || !value.functions.every(isFunctionIr)) {return false;}
  return true;
}

function isImportLink(value: unknown): value is ImportLink {
  if (!isRecord(value)) {return false;}
  if (typeof value.local !== 'string' || typeof value.specifier !== 'string' || typeof value.imported !== 'string') {
    return false;
  }
  return (
    optionalString(value, 'mappedSpecifier') &&
    optionalString(value, 'packageName') &&
    optionalString(value, 'exportTarget') &&
    optionalString(value, 'resolved')
  );
}

function isFunctionIr(value: unknown): value is FunctionIr {
  if (!isRecord(value) || typeof value.name !== 'string' || typeof value.file !== 'string') {return false;}
  if (!isInt(value.line, 0) || !isInt(value.col, 0)) {return false;}
  if (!Array.isArray(value.params) || !value.params.every(isParam)) {return false;}
  if (!Array.isArray(value.nodes) || !value.nodes.every(isNode)) {return false;}
  return true;
}

function isParam(value: unknown): value is IrParam {
  return isRecord(value) && typeof value.name === 'string' && isInt(value.id, 1);
}

function isNode(value: unknown): value is IrNode {
  if (!isNodeHeader(value)) {return false;}
  return isNodeSlots(value);
}

function isNodeHeader(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value) || typeof value.op !== 'string' || !OPS.has(value.op)) {return false;}
  if (typeof value.file !== 'string' || !isInt(value.line, 0) || !isInt(value.col, 0)) {return false;}
  return true;
}

function isNodeSlots(value: Record<string, unknown>): boolean {
  if (!optionalInt(value, 'dest') || !optionalInt(value, 'cond') || !optionalInt(value, 'object')) {return false;}
  if (value.name !== undefined && typeof value.name !== 'string') {return false;}
  if (value.args !== undefined && !isIntList(value.args)) {return false;}
  if ('literal' in value && !isLiteral(value.literal)) {return false;}
  return true;
}

function optionalInt(row: Record<string, unknown>, key: string): boolean {
  return row[key] === undefined || isInt(row[key], 1);
}

function isIntList(value: unknown): boolean {
  return Array.isArray(value) && value.every((item) => isInt(item, 1));
}

function isLiteral(value: unknown): boolean {
  return value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean';
}

function optionalString(row: Record<string, unknown>, key: string): boolean {
  return row[key] === undefined || typeof row[key] === 'string';
}

function isInt(value: unknown, min: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= min;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }
  if (isRecord(value)) {
    const keys = Object.keys(value).sort(cmp);
    return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function cmp(a: string, b: string): number {
  if (a < b) {return -1;}
  if (a > b) {return 1;}
  return 0;
}
