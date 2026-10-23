/**
 * Phase 455. GitLab CI untrusted inputs.
 * Off unless FULLSHIELD_EXPERIMENTAL_GITLABCI=1.
 * Flag off: the baseline finding list is returned unchanged.
 * The message says the variable is interpolated. This module does not call GitLab.
 */
import { parse as parseYaml } from 'yaml';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_GITLABCI';
export const GL_INJECT = 'CI-GL-INJECT-001';

/** Committed untrusted names. CI_JOB_ID is intentionally absent. */
const UNTRUSTED_GITLAB_VARS = [
  'CI_COMMIT_MESSAGE',
  'CI_COMMIT_TITLE',
  'CI_COMMIT_DESCRIPTION',
  'CI_COMMIT_REF_NAME',
  'CI_COMMIT_BRANCH',
  'CI_COMMIT_TAG',
  'CI_MERGE_REQUEST_TITLE',
  'CI_MERGE_REQUEST_DESCRIPTION',
  'CI_MERGE_REQUEST_SOURCE_BRANCH_NAME',
  'CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME',
] as const;

function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PhaseFinding {
  ruleId: string;
  severity: 'high';
  file: string;
  line: number;
  message: string;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function scriptsOf(value: unknown): string[] {
  if (typeof value === 'string') {
    return [value];
  }
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === 'string');
}

function interpolated(script: string): string | null {
  for (const name of UNTRUSTED_GITLAB_VARS) {
    if (script.includes(`$${name}`) || script.includes(`\${${name}}`)) {
      return name;
    }
  }
  return null;
}

export function scanGitlabCi(file: string, text: string, baseline: readonly PhaseFinding[] = []): PhaseFinding[] {
  if (!enabled()) {
    return [...baseline];
  }
  const root = asRecord(parseYaml(text) as unknown);
  if (root === null) {
    return [...baseline];
  }
  const findings: PhaseFinding[] = [];
  for (const [job, value] of Object.entries(root)) {
    const record = asRecord(value);
    if (record === null) {
      continue;
    }
    const scripts = [...scriptsOf(record.script), ...scriptsOf(record.before_script)];
    for (const script of scripts) {
      const name = interpolated(script);
      if (name !== null) {
        findings.push({
          ruleId: GL_INJECT,
          severity: 'high',
          file,
          line: 1,
          message: `job ${job} interpolates ${name}; the variable is interpolated`,
        });
        break;
      }
    }
  }
  return [...baseline, ...findings];
}
