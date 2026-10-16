#!/usr/bin/env node
/** Print each holdout app's ground truth as a Markdown table. Does not scan. */
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)));
const holdouts = JSON.parse(readFileSync(join(root, 'holdouts.json'), 'utf8'));

for (const app of holdouts.apps) {
  const file = join(root, app.name, 'ground-truth.json');
  console.log(`\n## ${app.name}\n`);
  console.log(`- status: \`${app.status}\``);
  console.log(`- reviewed: \`${app.reviewed}\``);
  console.log(`- repo: ${app.repo} @ \`${app.sha}\``);
  if (!existsSync(file)) {
    console.log('\nNo ground-truth file.\n');
    continue;
  }
  const doc = JSON.parse(readFileSync(file, 'utf8'));
  console.log('\n| class | file | line | inScope | source |');
  console.log('|---|---|---:|---|---|');
  for (const entry of doc.entries ?? []) {
    console.log(`| ${entry.class} | ${entry.file} | ${entry.line} | ${entry.inScope} | ${entry.source} |`);
  }
}
