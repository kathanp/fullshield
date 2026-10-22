/**
 * Phase 367. Private registry configuration.
 * Off unless FULLSHIELD_EXPERIMENTAL_PRIVREG=1.
 * Does not log in. Does not widen the home-directory read past phase 139.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_PRIVREG';
export const PHASE_139_FLAG = 'FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_HOME';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export function homeNpmrcAllowed(): boolean {
  return process.env[PHASE_139_FLAG] === '1';
}

export class FsError extends Error {
  readonly code = 'FS-E' as const;
  constructor(message: string) {
    super(message);
    this.name = 'FsError';
  }
}

export interface PrivRegFinding {
  ruleId: 'DEPS-PRIVREG-001';
  severity: 'high' | 'medium';
  file: string;
  message: string;
  /** Userinfo is already redacted. */
  registry: string;
}

export interface PrivRegConfig {
  /** Policy allowlist of registry hosts. Absent means no allowlist check. */
  allowlist?: readonly string[];
  /** Only `localhost` and `127.0.0.1` are accepted. */
  allowInsecureRegistryHosts?: readonly string[];
}

const LOCAL_INSECURE = new Set(['localhost', '127.0.0.1']);

export function assertInsecureHosts(hosts: readonly string[]): void {
  for (const host of hosts) {
    if (!LOCAL_INSECURE.has(host)) {
      throw new FsError(`allowInsecureRegistryHosts rejects ${host}`);
    }
  }
}

function redact(url: URL): string {
  const clone = new URL(url.href);
  if (clone.username !== '' || clone.password !== '') {
    clone.username = 'redacted';
    clone.password = '';
  }
  return clone.href;
}

export function registryFindings(file: string, npmrc: string, config: PrivRegConfig = {}): PrivRegFinding[] {
  if (!enabled()) {
    return [];
  }
  if (config.allowInsecureRegistryHosts !== undefined) {
    assertInsecureHosts(config.allowInsecureRegistryHosts);
  }
  const insecure = new Set(config.allowInsecureRegistryHosts ?? []);
  const findings: PrivRegFinding[] = [];
  for (const line of npmrc.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith(';')) {
      continue;
    }
    const match = /^(?:@[^:]+:)?registry=(.+)$/.exec(trimmed);
    const raw = match?.[1]?.trim();
    if (raw === undefined) {
      continue;
    }
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      continue;
    }
    const shown = redact(url);
    if (url.username !== '' || url.password !== '') {
      findings.push({
        ruleId: 'DEPS-PRIVREG-001',
        severity: 'high',
        file,
        registry: shown,
        message: `Registry URL in ${file} embeds userinfo (${shown}).`,
      });
    }
    if (url.protocol === 'http:') {
      const allowed = insecure.has(url.hostname);
      if (!allowed) {
        findings.push({
          ruleId: 'DEPS-PRIVREG-001',
          severity: 'high',
          file,
          registry: shown,
          message: `Registry URL in ${file} is http (${shown}).`,
        });
      }
    }
    if (config.allowlist !== undefined && !config.allowlist.includes(url.host)) {
      findings.push({
        ruleId: 'DEPS-PRIVREG-001',
        severity: 'medium',
        file,
        registry: shown,
        message: `Registry host ${url.host} is outside the policy allowlist.`,
      });
    }
  }
  return findings;
}

export function readRegistrySources(
  projectNpmrc: string | null,
  homeNpmrc: string | null,
  config: PrivRegConfig = {},
): PrivRegFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: PrivRegFinding[] = [];
  if (projectNpmrc !== null) {
    findings.push(...registryFindings('.npmrc', projectNpmrc, config));
  }
  if (homeNpmrc !== null && homeNpmrcAllowed()) {
    findings.push(...registryFindings('~/.npmrc', homeNpmrc, config));
  }
  return findings;
}
