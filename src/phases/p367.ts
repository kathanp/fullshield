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

function registryRaw(trimmed: string): string | undefined {
  if (trimmed === '' || trimmed.startsWith('#') || trimmed.startsWith(';')) {
    return undefined;
  }
  return /^(?:@[^:]+:)?registry=(.+)$/.exec(trimmed)?.[1]?.trim();
}

function registryRow(file: string, shown: string, severity: PrivRegFinding['severity'], message: string): PrivRegFinding {
  return { ruleId: 'DEPS-PRIVREG-001', severity, file, registry: shown, message };
}

function urlFindings(file: string, raw: string, config: PrivRegConfig, insecure: ReadonlySet<string>): PrivRegFinding[] {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return [];
  }
  const shown = redact(url);
  const findings: PrivRegFinding[] = [];
  if (url.username !== '' || url.password !== '') {
    findings.push(registryRow(file, shown, 'high', `Registry URL in ${file} embeds userinfo (${shown}).`));
  }
  if (url.protocol === 'http:' && !insecure.has(url.hostname)) {
    findings.push(registryRow(file, shown, 'high', `Registry URL in ${file} is http (${shown}).`));
  }
  if (config.allowlist !== undefined && !config.allowlist.includes(url.host)) {
    findings.push(registryRow(file, shown, 'medium', `Registry host ${url.host} is outside the policy allowlist.`));
  }
  return findings;
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
    const raw = registryRaw(line.trim());
    if (raw === undefined) {
      continue;
    }
    findings.push(...urlFindings(file, raw, config, insecure));
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
