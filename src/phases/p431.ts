/**
 * Phase 431. GitLab report files.
 * Off unless FULLSHIELD_EXPERIMENTAL_GITLABRPT=1.
 * Flag off: no GitLab files are written.
 * This module does not call the GitLab API.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_GITLABRPT';
export const SIDECAR = 'unmapped.json';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface GitLabFinding {
  id: string;
  name: string;
  message: string;
  description: string;
  severity: string;
  file?: string;
  line?: number;
  cwe?: string;
}

export interface GitLabFiles {
  written: boolean;
  sast: Record<string, unknown> | null;
  unmapped: Record<string, unknown> | null;
}

const REQUIRED = ['id', 'category', 'name', 'message', 'description', 'severity', 'location', 'scanner'] as const;

function vulnerability(finding: GitLabFinding): Record<string, unknown> | null {
  if (finding.file === undefined || finding.line === undefined) {
    return null;
  }
  return {
    id: finding.id,
    category: 'sast',
    name: finding.name,
    message: finding.message,
    description: finding.description,
    severity: finding.severity,
    location: { file: finding.file, start_line: finding.line },
    scanner: { id: 'fullshield', name: 'FullShield' },
    identifiers: finding.cwe === undefined ? [] : [{ type: 'cwe', name: `CWE-${finding.cwe}`, value: finding.cwe }],
  };
}

export function validateGitLabSast(doc: unknown): string[] {
  const errors: string[] = [];
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return ['GitLab report must be an object'];
  }
  const root = doc as Record<string, unknown>;
  const header = root.header as Record<string, unknown> | undefined;
  if (header?.sidecar !== SIDECAR) {
    errors.push('header must name unmapped.json');
  }
  if (!Array.isArray(root.vulnerabilities)) {
    errors.push('vulnerabilities must be an array');
    return errors;
  }
  for (const row of root.vulnerabilities) {
    if (typeof row !== 'object' || row === null) {
      errors.push('vulnerability must be an object');
      continue;
    }
    const record = row as Record<string, unknown>;
    for (const key of REQUIRED) {
      if (record[key] === undefined) {
        errors.push(`missing ${key}`);
      }
    }
  }
  return errors;
}

export function emitGitLab(findings: readonly GitLabFinding[]): GitLabFiles {
  if (!enabled()) {
    return { written: false, sast: null, unmapped: null };
  }
  const vulnerabilities: Record<string, unknown>[] = [];
  const unmapped: GitLabFinding[] = [];
  for (const finding of findings) {
    const row = vulnerability(finding);
    if (row === null) {
      unmapped.push(finding);
    } else {
      vulnerabilities.push(row);
    }
  }
  const sast = {
    version: '15.0.4',
    header: { sidecar: SIDECAR, note: 'findings that do not fit are listed in unmapped.json' },
    vulnerabilities,
  };
  return { written: true, sast, unmapped: { findings: unmapped } };
}
