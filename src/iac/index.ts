import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { makeFindingId, type Finding } from '../core/finding.js';

function finding(ruleId: string, title: string, message: string, file: string, severity: Finding['severity'] = 'high'): Finding {
  return {
    id: makeFindingId(ruleId, file, message),
    ruleId,
    module: 'config',
    title,
    severity,
    confidence: 'medium',
    file,
    message,
    remediation: 'Pin actions by SHA, drop pull_request_target, tighten permissions, close 0.0.0.0/0, encrypt storage, drop privileged.',
  };
}

function runBodies(text: string): string[] {
  const bodies: string[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const match = /^(\s*)(?:-\s+)?run:\s*(.*)$/.exec(lines[i] ?? '');
    if (match === null) {continue;}
    const indent = match[1]?.length ?? 0;
    let body = match[2] ?? '';
    if (body === '|' || body === '>') {
      const block: string[] = [];
      for (let j = i + 1; j < lines.length; j += 1) {
        const line = lines[j] ?? '';
        if (line.trim() === '') {
          block.push(line);
          continue;
        }
        const lead = line.match(/^\s*/)?.[0].length ?? 0;
        if (lead <= indent) {break;}
        block.push(line);
      }
      body = block.join('\n');
    }
    bodies.push(body);
  }
  return bodies;
}

function walk(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) {return out;}
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (['node_modules', 'dist', '.git'].includes(entry.name)) {continue;}
      walk(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

export function scanIac(dir: string, opts: { experimental?: boolean } = {}): Finding[] {
  if (!opts.experimental && process.env.FULLSHIELD_EXPERIMENTAL_IAC !== '1') {return [];}
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {return [];}
  const findings: Finding[] = [];
  for (const file of walk(dir)) {
    const rel = relative(dir, file).replaceAll('\\', '/');
    const text = readFileSync(file, 'utf8');
    if (rel.includes('.github/workflows/') && /\.ya?ml$/.test(rel)) {
      if (/uses:\s+\S+@v\d/.test(text) && !(/uses:\s+\S+@[0-9a-f]{40}/.test(text))) {
        findings.push(finding('IAC-GHA-UNPINNED-001', 'GitHub Action not pinned to a commit SHA', 'uses: tag instead of SHA', rel));
      }
      if (/pull_request_target/.test(text)) {
        findings.push(finding('IAC-GHA-PRTARGET-001', 'pull_request_target workflow', 'untrusted PR can run with base secrets', rel, 'critical'));
      }
      if (/pull_request_target/.test(text) && /actions\/checkout/.test(text) && /github\.event\.pull_request/.test(text)) {
        findings.push(
          finding(
            'IAC-GHA-PRCHECKOUT-001',
            'pull_request_target checks out pull-request code',
            'untrusted head can run with the base repository token',
            rel,
            'critical',
          ),
        );
      }
      if (runBodies(text).some((body) => /\$\{\{\s*github\.event\./.test(body))) {
        findings.push(
          finding(
            'IAC-GHA-INJECT-001',
            'Workflow run step interpolates github.event',
            'untrusted event text is passed to the shell',
            rel,
            'critical',
          ),
        );
      }
      if (/permissions:\s*\n\s+contents:\s*write/.test(text) || /permissions:\s+write-all/.test(text)) {
        findings.push(finding('IAC-GHA-PERMS-001', 'Overly broad GitHub Actions permissions', 'write-all or contents: write', rel));
      }
      if (/echo\s+\$\{\{\s*secrets\.|console\.(?:log|info|debug)\([^)]*secrets\./i.test(text)) {
        findings.push(finding('IAC-GHA-SECRETLOG-001', 'Secret written to workflow logs', 'echo or console of secrets.*', rel, 'critical'));
      }
    }
    if (/\.tf$/.test(rel)) {
      if (/acl\s*=\s*"public-read"|block_public_acls\s*=\s*false/.test(text)) {
        findings.push(finding('IAC-TF-S3PUBLIC-001', 'Public S3 bucket', 'public-read or public ACLs enabled', rel, 'critical'));
      }
      if (/0\.0\.0\.0\/0/.test(text) && /22|3306|5432/.test(text)) {
        findings.push(finding('IAC-TF-SGOPEN-001', 'Security group open to the world on a data/admin port', '0.0.0.0/0 on 22/3306/5432', rel, 'critical'));
      }
      if (/encrypted\s*=\s*false/.test(text)) {
        findings.push(finding('IAC-TF-UNENCRYPTED-001', 'Unencrypted cloud storage', 'encrypted = false', rel));
      }
    }
    if (/deployment\.ya?ml$|pod\.ya?ml$/.test(rel) || rel.includes('k8s/')) {
      if (/privileged:\s*true/.test(text) || /hostNetwork:\s*true/.test(text)) {
        findings.push(finding('IAC-K8S-PRIV-001', 'Privileged or hostNetwork Kubernetes pod', 'privileged/hostNetwork true', rel, 'critical'));
      }
    }
    if (/compose\.ya?ml$|docker-compose\.ya?ml$/.test(rel)) {
      if (/privileged:\s*true/.test(text)) {
        findings.push(finding('IAC-COMPOSE-PRIV-001', 'Privileged docker-compose service', 'privileged: true', rel, 'critical'));
      }
    }
  }
  return findings;
}
