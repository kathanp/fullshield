/**
 * Phase 442. Static rule-doc generator.
 * A dev script. Not a runtime flag. The Markdown file wins.
 * Output is offline HTML: no script and no external URL in a tag.
 */
import { readFileSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

export const FOOTER = 'The Markdown file wins.';

function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function ruleIdOf(markdown: string, fileName: string): string {
  const id = /^id:\s*(\S+)/m.exec(markdown)?.[1];
  if (id !== undefined) {
    return id;
  }
  return fileName.replace(/\.md$/, '');
}

export function renderRulePage(markdown: string, fileName: string): string {
  const id = escapeHtml(ruleIdOf(markdown, fileName));
  const body = escapeHtml(markdown);
  return `<!DOCTYPE html><html><head><title>${id}</title><style>body{font-family:sans-serif}</style></head><body><h1>${id}</h1><pre>${body}</pre><footer>${FOOTER}</footer></body></html>`;
}

export function generateRuleDocs(rulesDir: string, outDir: string): string[] {
  mkdirSync(outDir, { recursive: true });
  const names = readdirSync(rulesDir).filter((name) => name.endsWith('.md'));
  if (names.length === 0) {
    throw new TypeError(`no rule file in ${rulesDir}`);
  }
  const written: string[] = [];
  for (const name of names) {
    const markdown = readFileSync(join(rulesDir, name), 'utf8');
    const page = renderRulePage(markdown, name);
    const dest = join(outDir, name.replace(/\.md$/, '.html'));
    writeFileSync(dest, page);
    written.push(dest);
  }
  return written;
}

function isDirectRun(): boolean {
  const arg = process.argv[1];
  return arg !== undefined && arg.endsWith('p442.ts');
}

if (isDirectRun()) {
  const rulesDir = process.argv[2];
  const outDir = process.argv[3];
  if (rulesDir === undefined || outDir === undefined) {
    process.stderr.write('usage: phase442-ruledocs <rulesDir> <outDir>\n');
    process.exitCode = 1;
  } else {
    generateRuleDocs(rulesDir, outDir);
  }
}
