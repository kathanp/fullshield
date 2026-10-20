import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import type { CapabilityName } from './names.js';
import { signalsInText } from './signals.js';

const TEXT = /\.(?:[cm]?js|jsx|tsx?)$/;
const MAX_BYTES = 1_000_000;
const INSTALL = ['preinstall', 'install', 'postinstall'] as const;

function walk(dir: string, out: string[]): void {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') {continue;}
      walk(full, out);
      continue;
    }
    if (entry.isFile()) {out.push(full);}
  }
}

function installScripts(dir: string): boolean {
  const manifestPath = join(dir, 'package.json');
  if (!existsSync(manifestPath)) {return false;}
  try {
    const pkg = JSON.parse(readFileSync(manifestPath, 'utf8')) as { scripts?: Record<string, unknown> };
    const scripts = pkg.scripts ?? {};
    return INSTALL.some((key) => typeof scripts[key] === 'string');
  } catch {
    return false;
  }
}

function readText(file: string): string | undefined {
  try {
    if (statSync(file).size > MAX_BYTES) {return undefined;}
    return readFileSync(file, 'utf8');
  } catch {
    return undefined;
  }
}

function isNative(file: string): boolean {
  return file.endsWith('.node') || file.endsWith('binding.gyp');
}

/** Read already-installed package files. Never imports them and never runs scripts. */
export function detectPackage(dir: string): CapabilityName[] {
  const found = new Set<CapabilityName>();
  if (installScripts(dir)) {found.add('install_script');}
  const files: string[] = [];
  walk(dir, files);
  if (files.some(isNative)) {found.add('native');}
  for (const file of files) {
    if (!TEXT.test(file)) {continue;}
    const text = readText(file);
    if (text === undefined) {continue;}
    for (const cap of signalsInText(text)) {found.add(cap);}
  }
  return [...found].sort();
}
