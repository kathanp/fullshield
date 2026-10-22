#!/usr/bin/env node
/**
 * Phase 496. Threat-model document. reviewed stays false.
 * Marketing phrases from Section 31 are not copied into this file.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_THREATDOC';

export const SECTION_31 = [
  'Container image / OS package scanning (use Trivy/Grype)',
  'Host intrusion prevention, firewall management, OS-level IP blocking (use fail2ban, CrowdSec, cloud WAF)',
  'Scanning or attacking non-local hosts',
  'Cyber-physical / hardware-implant detection',
  'An LLM in the request path',
  'Telemetry of any kind',
  'Anything that auto-merges, auto-deploys, deletes code, edits lockfiles by hand, or publishes without human approval',
  'A VS Code extension',
  'A pull-request comment bot',
  "A new detection category before Phase 47's console acceptance passes",
  'Hiding `DEPS-VULN-001` or lowering its severity to shrink the NodeGoat count',
  'Bundling, mirroring, or downloading third-party rule registries (Semgrep registry or others)',
  "Running the project's tests or app to verify a fix (R15)",
  'Marketing words in any shipped file',
  'ML-based scoring',
];

export function threatModel() {
  const rejections = SECTION_31.map((line) => `- ${line}`).join('\n');
  return `---
reviewed: false
---

# Threat model

## Assets

- source under scan
- secrets in reports
- the OSV cache
- the runtime hook

## Trust boundary

The repo is untrusted and is not executed. The network is the R15 host list.

## Threats

### Tainted data reaches a sink
phase 5

### Secret value copied into a report
phase 340

### Substitution of the OSV cache
not covered

### Runtime hook tampering
phase 18

## Section 31 rejections

${rejections}
`;
}

export function checkThreatDoc(text) {
  const errors = [];
  if (!text.includes('reviewed: false')) errors.push('reviewed must stay false');
  if (/\nreviewed:\s*true/.test(text)) errors.push('reviewed must stay false');
  const threats = text.split('## Threats')[1]?.split('\n## ')[0] ?? '';
  const blocks = threats.split(/^### /m).slice(1);
  if (blocks.length === 0) errors.push('no threats');
  for (const block of blocks) {
    if (!/phase \d+/.test(block) && !block.includes('not covered')) {
      errors.push('a threat with no link and no not covered');
    }
  }
  for (const phrase of SECTION_31) {
    if (!text.includes(phrase)) errors.push(`missing opening phrase: ${phrase}`);
  }
  return errors;
}

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  const check = arg(argv, '--check');
  if (check !== undefined) {
    const errors = checkThreatDoc(readFileSync(check, 'utf8'));
    if (errors.length > 0) return { code: 1, stdout: '', stderr: `${errors.join('\n')}\n` };
    return { code: 0, stdout: 'threat model passes\n', stderr: '' };
  }
  const out = arg(argv, '--out');
  const text = threatModel();
  const errors = checkThreatDoc(text);
  if (errors.length > 0) return { code: 1, stdout: '', stderr: `${errors.join('\n')}\n` };
  if (out !== undefined) writeFileSync(out, text);
  return { code: 0, stdout: text, stderr: '' };
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
