/**
 * Phase 265. Reads floors. Never writes them.
 * Inactive until Section 41 item 2 is done.
 */
import { readFileSync } from 'node:fs';

function wilsonLower(successes, total) {
  if (total === 0) {return 0;}
  const z = 1.96;
  const p = successes / total;
  const z2 = z * z;
  const denom = 1 + z2 / total;
  const center = p + z2 / (2 * total);
  const margin = z * Math.sqrt((p * (1 - p) + z2 / (4 * total)) / total);
  return (center - margin) / denom;
}

const labelsPath = process.argv[2];
const floorsPath = process.argv[3];
if (labelsPath === undefined || floorsPath === undefined) {
  console.error('usage: precision-gate.mjs <labels.json> <floors.json>');
  process.exit(1);
}

console.log('precision gate inactive until Section 41 item 2 is done');
const labels = JSON.parse(readFileSync(labelsPath, 'utf8'));
const floors = JSON.parse(readFileSync(floorsPath, 'utf8'));
const groups = new Map();
for (const row of labels.rows ?? []) {
  const bucket = groups.get(row.rule) ?? [];
  bucket.push(row.label);
  groups.set(row.rule, bucket);
}

let failed = false;
for (const [rule, marks] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
  if (marks.length < 20) {
    console.log(`${rule} ungated ${marks.length}`);
    continue;
  }
  const tp = marks.filter((mark) => mark === 'tp').length;
  const bound = wilsonLower(tp, marks.length);
  const floor = floors[rule];
  const status = typeof floor === 'number' && bound < floor ? 'fail' : 'pass';
  if (status === 'fail') {failed = true;}
  console.log(`${rule} ${status} ${bound.toFixed(4)}`);
}
process.exit(failed ? 1 : 0);
