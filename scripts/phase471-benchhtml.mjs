#!/usr/bin/env node
/** Phase 471. Offline HTML for bench JSON already on disk. Does not scan. */
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_BENCHHTML';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function escapeHtml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

export function renderBenchFile(filePath) {
  const name = basename(filePath);
  if (!existsSync(filePath)) {
    return `<section data-file="${escapeHtml(name)}"><h2>${escapeHtml(name)}</h2><p>missing</p></section>`;
  }
  const raw = readFileSync(filePath, 'utf8');
  const doc = JSON.parse(raw);
  const stat = statSync(filePath);
  const unreviewed = doc.unreviewed === true ? 'true' : 'false';
  const body = escapeHtml(raw);
  return `<section data-file="${escapeHtml(name)}"><h2>${escapeHtml(name)}</h2><p>unreviewed: ${unreviewed}</p><p>mtime: ${stat.mtime.toISOString()}</p><pre>${body}</pre></section>`;
}

export function renderBenchHtml(paths) {
  const sections = paths.map((filePath) => renderBenchFile(filePath)).join('\n');
  return `<!DOCTYPE html>\n<html><head><meta charset="utf-8"><style>body{font-family:sans-serif}</style></head><body>\n${sections}\n</body></html>\n`;
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const files = [];
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--file') {
      const next = argv[i + 1];
      if (next !== undefined) files.push(next);
    }
  }
  const out = arg(argv, '--out');
  const html = renderBenchHtml(files);
  if (out !== undefined) writeFileSync(out, html);
  return { code: 0, stdout: html, stderr: '' };
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
