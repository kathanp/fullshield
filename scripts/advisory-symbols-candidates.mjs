import { readFileSync } from 'node:fs';

/**
 * Phase 260. Prints advisory ids already present in a local hit-count file.
 * It never writes models/advisory-symbols.json and never sets reviewed.
 */

const argv = process.argv.slice(2);
if (argv.some((arg) => arg === '--write' || arg === '--fill')) {
  console.error('advisory-symbols-candidates refuses to fill rows');
  process.exit(1);
}

const file = argv.find((arg) => arg.endsWith('.json'));
if (file === undefined) {
  console.log('candidates 0');
  process.exit(0);
}

const raw = JSON.parse(readFileSync(file, 'utf8'));
const rows = Array.isArray(raw.hits) ? raw.hits : [];
const ranked = rows
  .filter((row) => typeof row.id === 'string' && Number.isInteger(row.count))
  .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id))
  .slice(0, 100);

console.log(`candidates ${ranked.length}`);
for (const row of ranked) {console.log(`${row.id} ${row.count}`);}
