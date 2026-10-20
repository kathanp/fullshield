import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';

import { makeFindingId, type Finding } from '../../core/finding.js';
import { everyMatch, maskSecret, shannonEntropy } from './mask.js';
import { scanTextForSecretHits } from './index.js';
import type { SecretHit } from './types.js';

const BUNDLE_SUBDIRS = ['dist', '.next/static', 'build'];
const SKIP_DIRS = new Set(['node_modules', '.git', '.fullshield']);
const FILE_OK = /\.(?:[cm]?[jt]sx?|json|html?|css|map|env)(?:\..*)?$/i;
const ENV_NAME = /^\.env(?:\..+)?$/;
const PUBLIC_ENV =
  /\b((?:NEXT_PUBLIC_|VITE_)[A-Z0-9_]+)\s*[:=]\s*(?:["']([^"']{8,})["']|([^\s"'`,}]{8,}))/g;
const SECRETISH_NAME = /(SECRET|TOKEN|PASSWORD|PASSWD|PWD|KEY)/i;
const MAX_FILE = 1024 * 1024;

export interface BundleScanResult {
  findings: Finding[];
  hits: SecretHit[];
}

const BUNDLE_REMEDIATION =
  'Remove this value from client code. NEXT_PUBLIC_ and VITE_ names are inlined into the browser bundle. ' +
  'Rotate the credential; shipping a secret to clients cannot be undone by deleting the source line.';

function posixRel(root: string, full: string): string {
  return relative(root, full).split('\\').join('/');
}

async function listFiles(root: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) {continue;}
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) {continue;}
        await walk(full);
      } else if (entry.isFile()) {
        const base = entry.name;
        if (FILE_OK.test(base) || ENV_NAME.test(base)) {files.push(full);}
      }
    }
  }

  const roots = new Set<string>([root]);
  for (const sub of BUNDLE_SUBDIRS) {roots.add(join(root, sub));}
  for (const dir of roots) {
    try {
      const s = await stat(dir);
      if (s.isDirectory()) {await walk(dir);}
      else if (s.isFile()) {files.push(dir);}
    } catch {
      // missing conventional subdir
    }
  }
  return files;
}

function isSecretShaped(name: string, value: string): boolean {
  if (value.startsWith('pk_live_') || value.startsWith('pk_test_')) {return false;}
  if (/^https?:\/\//i.test(value)) {return false;}
  if (value.includes(' ') || value.includes('${')) {return false;}
  const probe = `const ${name} = "${value}";\n`;
  if (scanTextForSecretHits('bundle.js', probe).some((h) => h.secret !== undefined)) {return true;}
  if (!SECRETISH_NAME.test(name)) {return false;}
  return value.length >= 16 && shannonEntropy(value) > 4.5;
}

function publicEnvHits(rel: string, text: string): SecretHit[] {
  const hits: SecretHit[] = [];
  const folded = text.split(/\r?\n/).map((line) => line.replace(/(["'`])\s*\+\s*(["'`])/g, ''));
  folded.forEach((line, index) => {
    for (const match of everyMatch(PUBLIC_ENV, line)) {
      const name = match[1];
      const value = match[2] ?? match[3];
      if (name === undefined || value === undefined) {continue;}
      if (!isSecretShaped(name, value)) {continue;}
      const masked = maskSecret(value);
      const lineNo = index + 1;
      hits.push({
        finding: {
          id: makeFindingId('SECRET-BUNDLE-001', rel, `${lineNo}|${masked}`),
          ruleId: 'SECRET-BUNDLE-001',
          module: 'secrets',
          title: 'Secret-shaped value exposed to the browser',
          severity: 'high',
          confidence: 'medium',
          cwe: 'CWE-798',
          file: rel,
          line: lineNo,
          snippet: masked,
          message: `${name} is inlined into a client bundle (NEXT_PUBLIC_/VITE_* values are browser-visible).`,
          remediation: BUNDLE_REMEDIATION,
        },
        secret: value,
      });
    }
  });
  return hits;
}

/** Scan built client bundles for browser-exposed keys. Does not use config ignore. */
export async function scanBundle(root: string): Promise<BundleScanResult> {
  const hits: SecretHit[] = [];
  const seen = new Set<string>();
  for (const full of await listFiles(root)) {
    if (seen.has(full)) {continue;}
    seen.add(full);
    let text: string;
    try {
      text = await readFile(full, 'utf8');
    } catch {
      continue;
    }
    if (text.length > MAX_FILE || text.includes('\u0000')) {continue;}
    const rel = posixRel(root, full) || full;
    hits.push(...scanTextForSecretHits(rel, text), ...publicEnvHits(rel, text));
  }
  return { findings: hits.map((h) => h.finding), hits };
}
