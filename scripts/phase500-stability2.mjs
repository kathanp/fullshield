#!/usr/bin/env node
/** Phase 500. Stability section and removal window. Does not release 2.0 or edit default JSON. */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_STABILITY2';

export const STABLE_FIELDS = [
  'id',
  'ruleId',
  'module',
  'title',
  'severity',
  'confidence',
  'file',
  'line',
  'message',
  'remediation',
  'references',
  'trace',
];

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function matter(text) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (match === null) return {};
  const out = {};
  for (const line of (match[1] ?? '').split(/\r?\n/)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return out;
}

export function stableRuleIds(rulesDir) {
  const ids = [];
  for (const name of readdirSync(rulesDir).filter((file) => file.endsWith('.md')).sort()) {
    const meta = matter(readFileSync(join(rulesDir, name), 'utf8'));
    if (meta.stability === 'stable') ids.push(name.slice(0, -3));
  }
  return ids;
}

export function stabilitySection(ids) {
  return [
    '## Stable scan contract',
    '',
    'Stable scan fields:',
    ...STABLE_FIELDS.map((field) => `- ${field}`),
    '',
    'Stable rule ids:',
    ...(ids.length === 0 ? ['- (none)'] : ids.map((id) => `- ${id}`)),
    '',
  ].join('\n');
}

function minorOf(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (match === null) throw new Error(`bad version ${version}`);
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
}

export function checkDeprecationWindow(deprecatedIn, removedIn) {
  const from = minorOf(deprecatedIn);
  const to = minorOf(removedIn);
  if (to.major !== from.major) return { ok: false, reason: 'removal crossed a major' };
  const distance = to.minor - from.minor;
  if (distance < 2) return { ok: false, reason: 'deprecation removed one minor later' };
  return { ok: true, reason: 'removal is two minors later' };
}

export function checkSchema(required, bump) {
  const missing = STABLE_FIELDS.filter((field) => !required.includes(field));
  if (missing.length === 0) return { ok: true, missing };
  if (bump === 'major') return { ok: true, missing };
  return { ok: false, missing };
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const rules = arg(argv, '--rules');
  const ids = rules === undefined ? [] : stableRuleIds(rules);
  const section = stabilitySection(ids);
  if (section.includes('product is complete')) {
    return { code: 1, stdout: '', stderr: 'section claims the product is complete\n' };
  }
  const schemaPath = arg(argv, '--schema');
  if (schemaPath !== undefined) {
    const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
    const required = Array.isArray(schema.required) ? schema.required : [];
    const bump = arg(argv, '--bump') ?? 'minor';
    const checked = checkSchema(required, bump);
    if (!checked.ok) {
      return { code: 1, stdout: `${section}\n`, stderr: `stable field disappeared: ${checked.missing.join(', ')}\n` };
    }
  }
  const deprecated = arg(argv, '--deprecated');
  const removed = arg(argv, '--removed');
  if (deprecated !== undefined && removed !== undefined) {
    const window = checkDeprecationWindow(deprecated, removed);
    if (!window.ok) return { code: 1, stdout: `${section}\n`, stderr: `${window.reason}\n` };
  }
  return { code: 0, stdout: `${section}\n`, stderr: '' };
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
