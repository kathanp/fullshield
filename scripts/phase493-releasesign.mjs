#!/usr/bin/env node
/** Phase 493. Lint a release workflow's sign step and dry-run a fixture signature. No publish. */
import { createPrivateKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_RELEASESIGN';

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function jobsOf(text) {
  const jobs = [];
  const lines = text.split(/\r?\n/);
  let current = undefined;
  for (const line of lines) {
    const job = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (job !== null) {
      current = { name: job[1] ?? '', lines: [] };
      jobs.push(current);
      continue;
    }
    if (current !== undefined) current.lines.push(line);
  }
  return jobs;
}

function isRelease(job) {
  const blob = job.lines.join('\n');
  return job.name === 'release' || job.name === 'publish' || blob.includes("refs/tags");
}

function isPullRequest(job) {
  const blob = job.lines.join('\n');
  return job.name === 'pull_request' || blob.includes('pull_request');
}

export function lintWorkflow(text) {
  const errors = [];
  if (text.includes('upload-artifact') && /key\.pem|private\.key|SBOM_SIGN_KEY/.test(text) && /path:.*key/.test(text)) {
    errors.push('private key is an artifact path');
  }
  for (const job of jobsOf(text)) {
    const blob = job.lines.join('\n');
    const signStep = blob.includes('sbom-sign') || blob.includes('phase493-releasesign');
    if (!signStep) continue;
    if (/continue-on-error:\s*true/.test(blob)) errors.push('continue-on-error fails the lint');
    const hasSecret = /secrets\.[A-Z0-9_]+/.test(blob);
    if (isRelease(job) && !hasSecret) errors.push('release job missing the secret');
    if (isPullRequest(job) && !hasSecret) {
      /* a pull-request job without the secret does not fail */
    }
  }
  const releaseJobs = jobsOf(text).filter((job) => isRelease(job));
  for (const job of releaseJobs) {
    const blob = job.lines.join('\n');
    const signStep = blob.includes('sbom-sign') || blob.includes('phase493-releasesign');
    if (!signStep) errors.push('release job missing the sign command');
    else if (!/secrets\.[A-Z0-9_]+/.test(blob)) errors.push('release job missing the secret');
  }
  return errors;
}

export function dryRunSign(keyPath, sbomPath, outPath) {
  const key = createPrivateKey(readFileSync(keyPath));
  const bytes = readFileSync(sbomPath);
  const signature = sign(null, bytes, key);
  writeFileSync(outPath, signature);
}

export function signDocument(pem, sbomBytes) {
  const document = JSON.parse(sbomBytes.toString('utf8'));
  if (document === null || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error('sbom must be a JSON object');
  }
  const payload = Buffer.from(JSON.stringify(document));
  return sign(null, payload, createPrivateKey(pem));
}

function sbomSign(argv, env) {
  const secret = env.SBOM_SIGN_KEY ?? '';
  if (secret.length === 0) return { code: 1, stdout: '', stderr: 'release job missing the secret\n' };
  const sbom = arg(argv, '--sbom');
  const out = arg(argv, '--out');
  if (sbom === undefined || out === undefined) {
    return { code: 2, stdout: '', stderr: 'usage: --sbom-sign --sbom <file> --out <file>\n' };
  }
  let signature;
  try {
    signature = signDocument(secret, readFileSync(sbom));
  } catch {
    return { code: 1, stdout: '', stderr: 'sbom sign failed\n' };
  }
  writeFileSync(out, signature);
  return { code: 0, stdout: 'signature written\n', stderr: '' };
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  if (argv.includes('--sbom-sign')) return sbomSign(argv, env);
  const workflow = arg(argv, '--workflow');
  if (workflow !== undefined) {
    const errors = lintWorkflow(readFileSync(workflow, 'utf8'));
    if (errors.length > 0) return { code: 1, stdout: '', stderr: `${errors.join('\n')}\n` };
  }
  const key = arg(argv, '--key');
  const sbom = arg(argv, '--sbom');
  const out = arg(argv, '--out');
  if (key !== undefined && sbom !== undefined && out !== undefined) {
    dryRunSign(key, sbom, out);
    return { code: 0, stdout: 'signature written\n', stderr: '' };
  }
  if (workflow !== undefined) return { code: 0, stdout: 'workflow lint passes\n', stderr: '' };
  return { code: 2, stdout: '', stderr: 'usage: --workflow <file> or --key --sbom --out\n' };
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
