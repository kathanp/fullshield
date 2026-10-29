import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { sortFindings, type Finding } from '../core/finding.js';

const EXCEPTIONS_FLAG = 'FULLSHIELD_EXPERIMENTAL_EXCEPTIONS';
const EXCEPTIONS_FILE_NAME = 'fullshield.exceptions.json';
const MAX_EXCEPTION_WINDOW_MS = 365 * 24 * 60 * 60 * 1000;

function fail(message: string): never {
  const err = new Error(message);
  throw err;
}

export interface ExceptionRow {
  ruleId: string;
  owner: string;
  reason: string;
  expires: string;
  file?: string;
}

export interface AppliedExceptions {
  findings: Finding[];
  errors: string[];
}

function expiresAtMs(expires: string): number {
  if (/^\d{4}-\d{2}-\d{2}$/.test(expires)) {
    return Date.parse(`${expires}T23:59:59.999Z`);
  }
  return Date.parse(expires);
}

function assertExceptionWindow(expires: string, now: Date): void {
  const at = expiresAtMs(expires);
  if (!Number.isFinite(at)) {
    fail(`exceptions file expires is not an ISO date (${EXCEPTIONS_FLAG})`);
  }
  if (at - now.getTime() > MAX_EXCEPTION_WINDOW_MS) {
    fail(`exceptions file expiry exceeds 365 days (${EXCEPTIONS_FLAG})`);
  }
}

export function parseExceptions(raw: unknown): ExceptionRow[] {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    fail(`exceptions file must be an object (${EXCEPTIONS_FLAG})`);
  }
  const rows = (raw as { exceptions?: unknown }).exceptions;
  if (!Array.isArray(rows)) {
    fail(`exceptions file requires exceptions (${EXCEPTIONS_FLAG})`);
  }
  return rows.map((row) => {
    if (typeof row !== 'object' || row === null) {
      fail(`exceptions file requires owner, reason, and expires (${EXCEPTIONS_FLAG})`);
    }
    const item = row as Record<string, unknown>;
    if (typeof item.ruleId !== 'string' || item.ruleId.length === 0) {
      fail(`exceptions file requires owner, reason, and expires (${EXCEPTIONS_FLAG})`);
    }
    if (typeof item.owner !== 'string' || item.owner.length === 0) {
      fail(`exceptions file requires owner, reason, and expires (${EXCEPTIONS_FLAG})`);
    }
    if (typeof item.reason !== 'string' || item.reason.length === 0) {
      fail(`exceptions file requires owner, reason, and expires (${EXCEPTIONS_FLAG})`);
    }
    if (typeof item.expires !== 'string' || item.expires.length === 0) {
      fail(`exceptions file requires owner, reason, and expires (${EXCEPTIONS_FLAG})`);
    }
    const file = item.file;
    if (file !== undefined && (typeof file !== 'string' || file.length === 0)) {
      fail(`exceptions file requires owner, reason, and expires (${EXCEPTIONS_FLAG})`);
    }
    return {
      ruleId: item.ruleId,
      owner: item.owner,
      reason: item.reason,
      expires: item.expires,
      ...(typeof file === 'string' ? { file } : {}),
    };
  });
}

export function applyExceptions(
  findings: readonly Finding[],
  rows: readonly ExceptionRow[],
  now: Date,
): AppliedExceptions {
  const errors: string[] = [];
  const suppressed = new Set<string>();
  for (const row of rows) {
    assertExceptionWindow(row.expires, now);
    if (expiresAtMs(row.expires) < now.getTime()) {
      errors.push(
        `exception for ${row.ruleId} expired on ${row.expires} (owner: ${row.owner}); renew or remove it (${EXCEPTIONS_FLAG})`,
      );
      continue;
    }
    for (const finding of findings) {
      if (finding.ruleId !== row.ruleId) {continue;}
      if (row.file !== undefined && finding.file !== row.file) {continue;}
      suppressed.add(finding.id);
    }
  }
  return {
    findings: sortFindings(findings.filter((finding) => !suppressed.has(finding.id))),
    errors,
  };
}

export async function loadExceptions(cwd: string): Promise<ExceptionRow[] | undefined> {
  let text: string;
  try {
    text = await readFile(join(cwd, EXCEPTIONS_FILE_NAME), 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {return undefined;}
    fail(`cannot read exceptions file (${EXCEPTIONS_FLAG})`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text) as unknown;
  } catch {
    fail(`exceptions file is not JSON (${EXCEPTIONS_FLAG})`);
  }
  return parseExceptions(raw);
}
