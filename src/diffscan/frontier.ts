import { readFile } from 'node:fs/promises';
import { join, posix } from 'node:path';

import { gitOutput } from '../core/git.js';
import { raise } from '../core/raise.js';

const DIFFSCAN_FLAG = 'FULLSHIELD_EXPERIMENTAL_DIFFSCAN';

const SOURCE_EXT = /\.(jsx?|mjs|cjs|tsx?|mts|cts)$/;
const DECLARATION = /\.d\.ts$/;
const EXTS = ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts'];
const IMPORT_RE = /(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)['"](\.[^'"]+)['"]/g;

interface GitResult {
  status: number;
  stdout: string;
}

type GitRunner = (args: string[]) => Promise<GitResult>;

let lastChanged: readonly string[] = [];

export function diffChangedFiles(): readonly string[] {
  return lastChanged;
}

function isSourcePath(rel: string): boolean {
  const norm = rel.replaceAll('\\', '/');
  if (DECLARATION.test(norm)) {return false;}
  return SOURCE_EXT.test(norm);
}

function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:\\])\/\/.*$/gm, '$1');
}

function relativeSpecifiers(text: string): string[] {
  const out: string[] = [];
  for (const match of stripComments(text).matchAll(IMPORT_RE)) {
    const spec = match[1];
    if (spec !== undefined && spec.startsWith('.')) {out.push(spec);}
  }
  return out;
}

function resolveRelative(
  fromFile: string,
  spec: string,
  files: ReadonlySet<string>,
): string | undefined {
  const base = posix.normalize(posix.join(posix.dirname(fromFile), spec));
  const candidates = [base];
  for (const ext of EXTS) {
    candidates.push(`${base}${ext}`);
    candidates.push(posix.join(base, `index${ext}`));
  }
  for (const candidate of candidates) {
    if (files.has(candidate) && isSourcePath(candidate)) {return candidate;}
  }
  return undefined;
}

async function changedPaths(cwd: string, git?: GitRunner): Promise<string[]> {
  const run: GitRunner = git ?? ((args) => gitOutput(cwd, args));
  const diff = await run(['diff', '--name-only', 'HEAD']);
  if (diff.status !== 0) {raise(`${DIFFSCAN_FLAG} git failed`);}
  const untracked = await run(['ls-files', '--others', '--exclude-standard']);
  if (untracked.status !== 0) {raise(`${DIFFSCAN_FLAG} git failed`);}
  const names = new Set<string>();
  for (const line of `${diff.stdout}\n${untracked.stdout}`.split('\n')) {
    const name = line.trim().replaceAll('\\', '/');
    if (name.length > 0) {names.add(name);}
  }
  return [...names].sort();
}

function readRel(cwd: string, rel: string): Promise<string> {
  return readFile(join(cwd, rel), 'utf8');
}

/** Changed source files, their relative-literal imports, and their relative-literal importers. Hop cap is 1. */
export async function limitToFrontier(cwd: string, walked: readonly string[], git?: GitRunner): Promise<string[]> {
  const changed = await changedPaths(cwd, git);
  lastChanged = changed;
  const universe = new Set(walked.map((rel) => rel.replaceAll('\\', '/')));
  const changedSource = changed.filter((rel) => universe.has(rel) && isSourcePath(rel));
  const changedSet = new Set(changedSource);
  const frontier = new Set(changedSource);

  for (const rel of changedSource) {
    const text = await readRel(cwd, rel);
    for (const spec of relativeSpecifiers(text)) {
      const resolved = resolveRelative(rel, spec, universe);
      if (resolved !== undefined) {frontier.add(resolved);}
    }
  }

  for (const rel of universe) {
    if (!isSourcePath(rel) || changedSet.has(rel)) {continue;}
    const text = await readRel(cwd, rel);
    for (const spec of relativeSpecifiers(text)) {
      const resolved = resolveRelative(rel, spec, universe);
      if (resolved !== undefined && changedSet.has(resolved)) {
        frontier.add(rel);
        break;
      }
    }
  }

  return [...frontier].sort();
}
