#!/usr/bin/env node
/**
 * Phase 447. Diff the stable required keys of two scan-result schemas.
 * Usage: node scripts/phase447-schema-diff.mjs <previous.json> <next.json>
 * Each file is a JSON array of required property names, or an object with required[].
 */
import { readFileSync } from 'node:fs';

function requiredList(path) {
  const parsed = JSON.parse(readFileSync(path, 'utf8'));
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (parsed && Array.isArray(parsed.required)) {
    return parsed.required;
  }
  console.error('schema required list must be an array');
  process.exit(1);
}

const previousPath = process.argv[2];
const nextPath = process.argv[3];
if (previousPath === undefined || nextPath === undefined) {
  console.error('usage: phase447-schema-diff <previous.json> <next.json>');
  process.exit(1);
}

const previous = requiredList(previousPath);
const next = new Set(requiredList(nextPath));
const removed = previous.filter((key) => !next.has(key));
if (removed.length > 0) {
  console.error(`stable required key removed: ${removed.join(',')}`);
  process.exit(1);
}
console.log('stable required keys unchanged');
