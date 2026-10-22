#!/usr/bin/env node
/** Phase 491. Read publish-workflow YAML and check claimed provenance fields. Does not rewrite it. */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PROVSHAPE';
const FIELDS = [
  { name: 'subject', pattern: /(^|\n)\s*subject\s*:/ },
  { name: 'build type', pattern: /(^|\n)\s*buildType\s*:/ },
  { name: 'isolation', pattern: /(^|\n)\s*isolation\s*:/ },
];

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function missingFields(text) {
  return FIELDS.filter((field) => !field.pattern.test(text)).map((field) => field.name);
}

function lineValue(text, key) {
  const match = new RegExp(`^[^\\S\\n]*${key}[^\\S\\n]*:[^\\S\\n]*(.*)$`, 'm').exec(text);
  if (match === null) return undefined;
  return (match[1] ?? '').trim();
}

export function fieldProblems(text) {
  const problems = missingFields(text).map((field) => `missing field ${field}`);
  const subject = lineValue(text, 'subject');
  if (subject !== undefined && subject.length === 0) problems.push('sub-point: subject is empty');
  const buildType = lineValue(text, 'buildType');
  if (buildType !== undefined && !buildType.startsWith('https://')) {
    problems.push('sub-point: build type is not an https URL');
  }
  const isolation = lineValue(text, 'isolation');
  if (isolation !== undefined && isolation !== 'hosted' && isolation !== 'self-hosted' && isolation !== 'sandboxed') {
    problems.push('sub-point: isolation is not hosted, self-hosted, or sandboxed');
  }
  return problems;
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const workflow = arg(argv, '--workflow');
  if (workflow === undefined) return { code: 2, stdout: '', stderr: 'usage: --workflow <file>\n' };
  const before = createHash('sha256').update(readFileSync(workflow)).digest('hex');
  const text = readFileSync(workflow, 'utf8');
  const problems = fieldProblems(text);
  const after = createHash('sha256').update(readFileSync(workflow)).digest('hex');
  if (before !== after) return { code: 1, stdout: '', stderr: 'checker rewrote the workflow\n' };
  if (problems.length > 0) {
    const park = argv.includes('--repo') ? 'parked (S3): ' : '';
    return { code: 1, stdout: '', stderr: `${park}${problems.join('\n')}\n` };
  }
  return { code: 0, stdout: 'provenance shape passes\n', stderr: '' };
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
