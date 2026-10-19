#!/usr/bin/env node
/**
 * Phase 73. Evidence only. This script does not promote a flag and does not scan holdouts.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const FLAGS = [
  'FULLSHIELD_EXPERIMENTAL_TAINT_V2',
  'FULLSHIELD_EXPERIMENTAL_SAST_GAPS',
  'FULLSHIELD_EXPERIMENTAL_FRAMEWORKS',
  'FULLSHIELD_EXPERIMENTAL_CLASSES',
];

export function promotionMarkdown(flag) {
  return [
    `# ${flag}`,
    '',
    'Status: not promoted. This file is evidence for a human. Cursor does not promote this flag.',
    '',
    '## Tuning-app key diff (seen)',
    '',
    'unmet — tuning apps were not scanned by this report run.',
    '',
    '## Crash count',
    '',
    'unmet — `bench/realworld.json` corpus was not executed here.',
    '',
    '## default-scan-diff if promoted',
    '',
    'not produced. Promotion was not performed.',
    '',
    '## Criteria not met',
    '',
    '- Phase 43 promotion criteria are not met in this report.',
    '- unmet — needs Phase 68 run after review',
    '',
  ].join('\n');
}

export function writePromotionReports(dir) {
  mkdirSync(dir, { recursive: true });
  for (const flag of FLAGS) {
    writeFileSync(join(dir, `${flag}.md`), promotionMarkdown(flag));
  }
  return FLAGS;
}

function arg(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const dir = arg('--out') ?? join(process.cwd(), 'bench/promotion');
  writePromotionReports(dir);
  console.log(`promotion-report wrote ${FLAGS.length} files to ${dir}`);
}
