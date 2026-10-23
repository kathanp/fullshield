/**
 * Phase 452. Compose services.
 * Off unless FULLSHIELD_EXPERIMENTAL_COMPOSE=1.
 * Flag off: the baseline finding list is returned unchanged.
 * Does not call a container runtime.
 */
import { parse as parseYaml } from 'yaml';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_COMPOSE';

export const COMPOSE_PRIVILEGED = 'CONFIG-COMPOSE-PRIVILEGED-001';
export const COMPOSE_HOSTNET = 'CONFIG-COMPOSE-HOSTNET-001';
export const COMPOSE_SOCKET = 'CONFIG-COMPOSE-SOCKET-001';
export const COMPOSE_ENVFILE = 'CONFIG-COMPOSE-ENVFILE-001';
export const COMPOSE_PORT = 'CONFIG-COMPOSE-PORT-001';

const SECRET = /\bAKIA[0-9A-Z]{16}\b/;
const BARE_INTERP = /\$\{[A-Za-z_][A-Za-z0-9_]*\}/;
const DEFAULT_INTERP = /\$\{[A-Za-z_][A-Za-z0-9_]*:-[^}]+\}/;

function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PhaseFinding {
  ruleId: string;
  severity: 'info' | 'low' | 'medium' | 'high';
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

function lineOf(text: string, needle: string): number {
  const lines = text.split(/\r?\n/);
  const index = lines.findIndex((line) => line.includes(needle));
  return index < 0 ? 1 : index + 1;
}

function stringsOf(value: unknown): string[] {
  if (typeof value === 'string') {
    return [value];
  }
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === 'string');
}

function isNodeApp(service: Record<string, unknown>, packageName: string): boolean {
  if (service.build !== undefined) {
    return true;
  }
  const image = typeof service.image === 'string' ? service.image : '';
  return image.includes(packageName);
}

function secretLiteral(value: string): boolean {
  if (BARE_INTERP.test(value) && !DEFAULT_INTERP.test(value)) {
    return false;
  }
  const defaults = value.match(DEFAULT_INTERP) ?? [];
  if (defaults.some((item) => SECRET.test(item))) {
    return true;
  }
  if (value.includes('${')) {
    return false;
  }
  return SECRET.test(value);
}

function scanService(name: string, service: Record<string, unknown>, file: string, text: string, packageName: string, envFiles: Readonly<Record<string, string>>): PhaseFinding[] {
  const findings: PhaseFinding[] = [];
  if (service.privileged === true) {
    findings.push({ ruleId: COMPOSE_PRIVILEGED, severity: 'high', file, line: lineOf(text, 'privileged'), message: `service ${name} sets privileged` });
  }
  if (service.network_mode === 'host') {
    findings.push({ ruleId: COMPOSE_HOSTNET, severity: 'high', file, line: lineOf(text, 'network_mode'), message: `service ${name} uses network_mode host` });
  }
  const volumes = stringsOf(service.volumes);
  if (volumes.some((item) => item.includes('docker.sock'))) {
    findings.push({ ruleId: COMPOSE_SOCKET, severity: 'high', file, line: lineOf(text, 'docker.sock'), message: `service ${name} mounts the docker socket` });
  }
  for (const envPath of stringsOf(service.env_file)) {
    const body = envFiles[envPath] ?? '';
    if (SECRET.test(body)) {
      findings.push({ ruleId: COMPOSE_ENVFILE, severity: 'high', file, line: lineOf(text, envPath), message: `service ${name} env_file matches a secret` });
    }
  }
  const env = asRecord(service.environment);
  if (env !== null) {
    for (const value of Object.values(env)) {
      if (typeof value === 'string' && secretLiteral(value)) {
        findings.push({ ruleId: COMPOSE_ENVFILE, severity: 'high', file, line: lineOf(text, value.slice(0, 20)), message: `service ${name} environment default is a secret literal` });
      }
    }
  }
  const ports = service.ports;
  const published = Array.isArray(ports) ? ports.length > 0 : typeof ports === 'string';
  if (published) {
    const severity = isNodeApp(service, packageName) ? 'medium' : 'low';
    findings.push({ ruleId: COMPOSE_PORT, severity, file, line: lineOf(text, 'ports'), message: `service ${name} publishes a port` });
  }
  return findings;
}

export function scanCompose(file: string, text: string, packageName: string, envFiles: Readonly<Record<string, string>> = {}, baseline: readonly PhaseFinding[] = []): PhaseFinding[] {
  if (!enabled()) {
    return [...baseline];
  }
  const parsed = parseYaml(text) as unknown;
  const root = asRecord(parsed);
  const services = asRecord(root?.services);
  if (services === null) {
    return [...baseline];
  }
  const findings: PhaseFinding[] = [];
  for (const [name, value] of Object.entries(services)) {
    const service = asRecord(value);
    if (service !== null) {
      findings.push(...scanService(name, service, file, text, packageName, envFiles));
    }
  }
  return [...baseline, ...findings];
}
