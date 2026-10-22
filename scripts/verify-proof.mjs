/**
 * Phase 262 verifier. Separate from the engine: this file imports no scanner code.
 * A step must exist, and each step's value is used by the next step's line.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function fail(message) {
  console.error(message);
  process.exit(1);
}

const proofPath = process.argv[2];
const root = process.argv[3] ?? process.cwd();
if (proofPath === undefined) {fail('usage: verify-proof.mjs <proof.json> [root]');}

const proof = JSON.parse(readFileSync(proofPath, 'utf8'));
if (!Array.isArray(proof.steps) || proof.steps.length === 0) {fail('proof has no steps');}

const cache = new Map();
function linesOf(file) {
  if (!cache.has(file)) {
    cache.set(file, readFileSync(resolve(root, file), 'utf8').split('\n'));
  }
  return cache.get(file);
}

for (let index = 0; index < proof.steps.length; index += 1) {
  const step = proof.steps[index];
  if (typeof step.file !== 'string' || typeof step.line !== 'number' || typeof step.value !== 'string' || typeof step.op !== 'string') {
    fail('step is missing file, line, op, or value');
  }
  const lines = linesOf(step.file);
  const text = lines[step.line - 1];
  if (text === undefined) {fail(`missing line ${step.file}:${step.line}`);}
  if (!text.includes(step.value) && !text.includes(step.op)) {fail(`step ${index} is not on ${step.file}:${step.line}`);}
  const next = proof.steps[index + 1];
  if (next !== undefined) {
    const nextText = linesOf(next.file)[next.line - 1] ?? '';
    if (!nextText.includes(step.value)) {fail(`step ${index} value ${step.value} is not used by the next step`);}
  }
}

console.log(`proof ok ${proof.steps.length}`);
