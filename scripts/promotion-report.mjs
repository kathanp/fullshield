#!/usr/bin/env node
/** List experimental flags. None are promoted; each criterion is unmet without evidence. */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const experimental = readFileSync(join(root, 'src', 'modules', 'sast', 'experimental.ts'), 'utf8');
const flags = [...experimental.matchAll(/FULLSHIELD_EXPERIMENTAL_[A-Z0-9_]+/g)].map((m) => m[0]);
const unique = [...new Set(flags)];

const lines = [
  '# Promotion report',
  '',
  'No flag is promoted. Promotion needs human approval and the evidence listed in the spec.',
  '',
  '| flag | recall on a reviewed untouched app | runtime p95 | crashes on the phase 41 corpus | decision |',
  '|---|---|---|---|---|',
];
for (const flag of unique) {
  lines.push(`| \`${flag}\` | unmet (no reviewed untouched scan) | unmet (not measured) | unmet (corpus not scanned) | keep experimental |`);
}
lines.push('');
lines.push('Promoted flags would become no-ops for one minor release. None are no-ops today.');
lines.push('');
process.stdout.write(`${lines.join('\n')}\n`);
