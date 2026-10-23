#!/usr/bin/env node
/** Phase 476. Render perf JSON with the phase 471 page. Not a gate. */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { renderBenchHtml } from './phase471-benchhtml.mjs';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PERFPAGE';
const HEADER = 'This page is not a gate.';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function renderPerfPage(paths) {
  const body = renderBenchHtml(paths);
  return `<!DOCTYPE html>\n<html><head><meta charset="utf-8"></head><body>\n<p>${HEADER}</p>\n${body}</body></html>\n`;
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
  const html = renderPerfPage(files);
  const out = arg(argv, '--out');
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
