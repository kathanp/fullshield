import { AsyncLocalStorage } from 'node:async_hooks';

import type { RaspRequestContext } from './types.js';

const SKIP_HEADERS = new Set([
  'host',
  'connection',
  'user-agent',
  'accept',
  'accept-encoding',
  'accept-language',
  'content-type',
  'content-length',
  'transfer-encoding',
  'cookie',
]);

const storage = new AsyncLocalStorage<RaspRequestContext>();

function flatten(value: unknown, out: string[], depth: number): void {
  if (depth > 8 || out.length > 200) {return;}
  if (typeof value === 'string') {
    out.push(value);
    return;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    out.push(String(value));
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {flatten(item, out, depth + 1);}
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value as Record<string, unknown>)) {flatten(child, out, depth + 1);}
  }
}

function collectObjects(value: unknown, out: unknown[], depth: number): void {
  if (depth > 8 || value === null || typeof value !== 'object') {return;}
  out.push(value);
  if (Array.isArray(value)) {
    for (const item of value) {collectObjects(item, out, depth + 1);}
    return;
  }
  for (const child of Object.values(value as Record<string, unknown>)) {collectObjects(child, out, depth + 1);}
}

export interface IncomingLike {
  path?: string;
  url?: string;
  ip?: string;
  query?: unknown;
  body?: unknown;
  params?: unknown;
  headers?: Record<string, unknown>;
  cookies?: unknown;
}

export function contextFromRequest(req: IncomingLike): RaspRequestContext {
  const strings: string[] = [];
  const objects: unknown[] = [];
  for (const value of [req.query, req.body, req.params, req.cookies]) {
    flatten(value, strings, 0);
    collectObjects(value, objects, 0);
  }
  if (req.headers && typeof req.headers === 'object') {
    for (const [key, value] of Object.entries(req.headers)) {
      if (SKIP_HEADERS.has(key.toLowerCase())) {continue;}
      flatten(value, strings, 0);
    }
    collectObjects(req.headers, objects, 0);
  }
  return {
    path: req.path ?? req.url?.split('?')[0] ?? '/',
    ip: req.ip ?? 'unknown',
    strings,
    objects,
  };
}

export function enterRaspContext<T>(ctx: RaspRequestContext, fn: () => T): T {
  return storage.run(ctx, fn);
}

export function currentRaspContext(): RaspRequestContext | undefined {
  return storage.getStore();
}
