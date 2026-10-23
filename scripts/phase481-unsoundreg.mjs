#!/usr/bin/env node
/** Phase 481. Compare an unsoundness enum to doc headings. Does not invent reasons. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_UNSOUNDREG';
export const OPENING = 'exhaustion over-approximates in sound mode and does not drop facts silently';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function kindsFromEnum(text) {
  const match = /UNSOUND_KINDS\s*=\s*\[([\s\S]*?)\]/.exec(text);
  if (match === null) return [];
  const body = match[1] ?? '';
  return [...body.matchAll(/'([^']+)'|"([^"]+)"/g)].map((hit) => hit[1] ?? hit[2] ?? '').filter((kind) => kind.length > 0);
}

export function headings(text) {
  return [...text.matchAll(/^##\s+(.+)$/gm)].map((hit) => (hit[1] ?? '').trim());
}

export function reasonGaps(docText, kinds) {
  const lines = docText.split(/\r?\n/);
  const gaps = [];
  for (const kind of kinds) {
    const start = lines.findIndex((line) => line.trim() === `## ${kind}`);
    if (start === -1) continue;
    let body = '';
    for (let index = start + 1; index < lines.length; index += 1) {
      const line = lines[index] ?? '';
      if (line.startsWith('## ')) break;
      body += line;
    }
    if (body.trim().length === 0) gaps.push(kind);
  }
  return gaps;
}

export function checkUnsoundness(enumText, docText) {
  const errors = [];
  if (!docText.toLowerCase().includes(OPENING)) errors.push('opening sentence is absent');
  if (docText.toLowerCase().includes('the engine is sound')) errors.push('the doc says the engine is sound');
  if (!/^---\r?\n[\s\S]*?reviewed:\s*false/.test(docText)) errors.push('reviewed must stay false');
  const kinds = kindsFromEnum(enumText);
  const heads = new Set(headings(docText));
  for (const kind of kinds) {
    if (!heads.has(kind)) errors.push(`missing heading for ${kind}`);
  }
  for (const head of heads) {
    if (!kinds.includes(head) && head !== 'Opening') errors.push(`heading is not a kind: ${head}`);
  }
  for (const kind of reasonGaps(docText, kinds)) {
    errors.push(`reason absent (human-owned): ${kind}`);
  }
  return errors;
}

function repoPaths() {
  const enumPath = fileURLToPath(new URL('../src/phases/p271.ts', import.meta.url));
  const docPath = fileURLToPath(new URL('../docs/unsoundness.md', import.meta.url));
  return { enumPath, docPath };
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const defaults = argv.includes('--repo') ? repoPaths() : undefined;
  const enumPath = arg(argv, '--enum') ?? defaults?.enumPath;
  const docPath = arg(argv, '--doc') ?? defaults?.docPath;
  if (enumPath === undefined || docPath === undefined) {
    return { code: 3, stdout: '', stderr: 'parked (S3): unsoundness enum file was not supplied\n' };
  }
  const before = readFileSync(docPath, 'utf8');
  const errors = checkUnsoundness(readFileSync(enumPath, 'utf8'), before);
  if (readFileSync(docPath, 'utf8') !== before) {
    return { code: 1, stdout: '', stderr: 'checker rewrote the doc\n' };
  }
  if (errors.length > 0) return { code: 1, stdout: '', stderr: `${errors.join('\n')}\n` };
  return { code: 0, stdout: 'unsoundness headings match\n', stderr: '' };
}

function isDirect() {
  const entry = process.argv[1];
  return entry !== undefined && fileURLToPath(import.meta.url) === entry;
}

if (isDirect()) {
  const result = main();
  if (result.stdout !== '') process.stdout.write(result.stdout);
  if (result.stderr !== '') process.stderr.write(result.stderr);
  process.exit(result.code);
}
