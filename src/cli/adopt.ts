import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const ADOPT_FLAG = 'FULLSHIELD_EXPERIMENTAL_ADOPT';

const STACKS = new Set(['express', 'nest', 'next', 'fastify', 'hono']);

function fail(message: string): never {
  const err = new Error(message);
  throw err;
}

function assertAdopt(): void {
  if (process.env[ADOPT_FLAG] !== '1') {fail(`${ADOPT_FLAG} is required`);}
}

function tourLines(): string[] {
  assertAdopt();
  return [
    '1. fullshield scan',
    '2. fullshield fix --dry-run',
    '3. fullshield init --ci',
    '4. This tour does not run project tests.',
    '5. This tour does not scan the home directory.',
  ];
}

export function stackNote(name: string): string {
  assertAdopt();
  if (!STACKS.has(name)) {fail(`${ADOPT_FLAG} unknown stack`);}
  return `# ${name}\n\nmode: monitor\n\nThis note does not suppress a finding.\n`;
}

function writeStack(cwd: string, name: string, force: boolean): string | undefined {
  const note = stackNote(name);
  const path = join(cwd, 'fullshield.stack.md');
  if (existsSync(path) && !force) {return undefined;}
  writeFileSync(path, note);
  return path;
}

export function adoptOutput(cwd: string, opts: { tour: boolean; stack?: string; force: boolean }): string[] {
  const lines: string[] = [];
  if (opts.tour) {lines.push(...tourLines());}
  if (opts.stack !== undefined) {
    const written = writeStack(cwd, opts.stack, opts.force);
    const line = written === undefined
      ? 'Nothing to write (files already exist). Pass --force to overwrite.'
      : `Wrote ${written}`;
    lines.push(line);
  }
  return lines;
}

function npmIds(doc: unknown): string[] {
  if (!Array.isArray(doc)) {fail(`${ADOPT_FLAG} digest file must be an array`);}
  const ids: string[] = [];
  for (const row of doc) {
    if (row === null || typeof row !== 'object') {continue;}
    const rec = row as { id?: unknown; ecosystem?: unknown };
    if (rec.ecosystem !== 'npm' || typeof rec.id !== 'string' || rec.id === '') {continue;}
    ids.push(rec.id);
  }
  return [...new Set(ids)].sort();
}

export function digestFile(path: string): string[] {
  assertAdopt();
  let doc: unknown;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  } catch (err) {
    if (err instanceof SyntaxError) {fail(`${ADOPT_FLAG} digest file is not JSON`);}
    throw err;
  }
  return npmIds(doc);
}
