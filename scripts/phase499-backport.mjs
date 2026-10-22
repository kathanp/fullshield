#!/usr/bin/env node
/** Phase 499. Diff stable finding keys against a second checkout. Does not publish or push. */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_BACKPORT';

export const SUPPORT_DOC = `# Support

Supported minor lines: 1.2.

The human backports security fixes for stable rule ids.
`;

function arg(argv, name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function loadFindings(path, root) {
  const doc = JSON.parse(readFileSync(path, 'utf8'));
  const rows = Array.isArray(doc) ? doc : doc.findings;
  return (rows ?? []).map((row) => {
    const file = String(row.file ?? '');
    const rootPrefix = root.length === 0 ? '' : root.endsWith('/') || root.endsWith('\\') ? root : `${root}/`;
    const rel = rootPrefix.length > 0 && file.startsWith(rootPrefix) ? relative(root, file) : file;
    return JSON.stringify({
      ruleId: row.ruleId,
      file: rel.replaceAll('\\', '/'),
      severity: row.severity,
    });
  });
}

export function diffKeys(leftPath, rightPath, leftRoot, rightRoot, stable) {
  const left = loadFindings(leftPath, leftRoot);
  const right = loadFindings(rightPath, rightRoot);
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  const onlyLeft = left.filter((key) => !rightSet.has(key));
  const onlyRight = right.filter((key) => !leftSet.has(key));
  const changed = [...onlyLeft, ...onlyRight];
  const stableChanged = changed.filter((key) => {
    const ruleId = JSON.parse(key).ruleId;
    return stable.has(ruleId);
  });
  return { changed, stableChanged };
}

export function main(argv = process.argv.slice(2), env = process.env) {
  if (env[FLAG] !== '1') return { code: 0, stdout: '', stderr: '' };
  if (argv.includes('--print-support')) return { code: 0, stdout: SUPPORT_DOC, stderr: '' };
  const out = arg(argv, '--support-out');
  if (out !== undefined) writeFileSync(out, SUPPORT_DOC);
  const other = arg(argv, '--other');
  if (other === undefined || !existsSync(other)) {
    return { code: 0, stdout: 'no backport target\n', stderr: '' };
  }
  const left = arg(argv, '--left');
  const right = arg(argv, '--right');
  const leftRoot = arg(argv, '--left-root') ?? '';
  const rightRoot = arg(argv, '--right-root') ?? '';
  const stable = new Set(
    (arg(argv, '--stable') ?? '')
      .split(',')
      .map((id) => id.trim())
      .filter((id) => id.length > 0),
  );
  if (left === undefined || right === undefined) {
    return { code: 2, stdout: '', stderr: 'usage: --left <json> --right <json> --other <dir>\n' };
  }
  const { stableChanged } = diffKeys(left, right, leftRoot, rightRoot, stable);
  if (stableChanged.length > 0) {
    return { code: 1, stdout: '', stderr: `stable id differs\n${stableChanged.join('\n')}\n` };
  }
  return { code: 0, stdout: 'stable keys match\n', stderr: '' };
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
