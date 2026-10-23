/**
 * Phase 380. Advisory cache age.
 * Off unless FULLSHIELD_EXPERIMENTAL_CACHEAGE=1.
 * Stats the cache. Does not refresh and does not GET.
 */
import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CACHEAGE';
export const DEFAULT_MAX_AGE_HOURS = 48;

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface CacheAgeFinding {
  ruleId: 'DEPS-ADVISORY-STALE-001';
  severity: 'info';
  age: number | null;
  cacheMtime: string | null;
  now: string;
  message: string;
}

function newestMtime(cacheDir: string): number | null {
  let newest: number | null = null;
  let entries: string[];
  try {
    entries = readdirSync(cacheDir);
  } catch {
    return null;
  }
  const pending = entries.map((name) => join(cacheDir, name));
  for (const full of pending) {
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      const nested = newestMtime(full);
      if (nested !== null && (newest === null || nested > newest)) {
        newest = nested;
      }
      continue;
    }
    if (newest === null || st.mtimeMs > newest) {
      newest = st.mtimeMs;
    }
  }
  return newest;
}

export function advisoryCacheAge(cacheDir: string | null, now = Date.now(), maxAgeHours = DEFAULT_MAX_AGE_HOURS): CacheAgeFinding[] {
  if (!enabled()) {
    return [];
  }
  const nowIso = new Date(now).toISOString();
  if (cacheDir === null) {
    return [
      {
        ruleId: 'DEPS-ADVISORY-STALE-001',
        severity: 'info',
        age: null,
        cacheMtime: null,
        now: nowIso,
        message: `Advisory cache is missing. age: null. now: ${nowIso}. This row is not a vulnerability.`,
      },
    ];
  }
  const mtime = newestMtime(cacheDir);
  if (mtime === null) {
    return [
      {
        ruleId: 'DEPS-ADVISORY-STALE-001',
        severity: 'info',
        age: null,
        cacheMtime: null,
        now: nowIso,
        message: `Advisory cache is missing. age: null. now: ${nowIso}. This row is not a vulnerability.`,
      },
    ];
  }
  const age = Math.floor((now - mtime) / 3_600_000);
  if (age <= maxAgeHours) {
    return [];
  }
  const mtimeIso = new Date(mtime).toISOString();
  return [
    {
      ruleId: 'DEPS-ADVISORY-STALE-001',
      severity: 'info',
      age,
      cacheMtime: mtimeIso,
      now: nowIso,
      message: `Advisory cache age is ${age} hours. cache mtime: ${mtimeIso}. now: ${nowIso}. This row is not a vulnerability.`,
    },
  ];
}
