/**
 * Phase 453. Kubernetes manifests for the Node workload.
 * Off unless FULLSHIELD_EXPERIMENTAL_K8SMANIFEST=1.
 * Flag off: the baseline finding list is returned unchanged.
 * A mention counts only in image, command, args, or a catalog label.
 */
import { parseAllDocuments } from 'yaml';

export const FLAG = 'FULLSHIELD_EXPERIMENTAL_K8SMANIFEST';
export const K8S_ROOT = 'CONFIG-K8S-ROOT-001';
export const K8S_PRIVILEGED = 'CONFIG-K8S-PRIVILEGED-001';
export const K8S_HOSTPATH = 'CONFIG-K8S-HOSTPATH-001';
export const K8S_MEM = 'CONFIG-K8S-MEMLIMIT-001';
export const K8S_TOKEN = 'CONFIG-K8S-SATOKEN-001';
export const K8S_SECRET = 'CONFIG-K8S-SECRET-001';

const SECRET = /\bAKIA[0-9A-Z]{16}\b/;
const LABEL_KEYS = new Set(['app', 'app.kubernetes.io/name']);

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface PhaseFinding {
  ruleId: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  file: string;
  line: number;
  message: string;
  snippet?: string;
}

export interface PhaseEvent {
  kind: 'parser-failure';
  file: string;
  line: number;
  reason: string;
}

export interface K8sResult {
  findings: PhaseFinding[];
  events: PhaseEvent[];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function textHit(value: unknown, packageName: string): boolean {
  if (typeof value === 'string') {
    return value.includes(packageName) || value.startsWith('node:');
  }
  if (Array.isArray(value)) {
    return value.some((item) => textHit(item, packageName));
  }
  return false;
}

function labelHit(value: unknown, packageName: string): boolean {
  const record = asRecord(value);
  if (record === null) {
    return false;
  }
  return Object.entries(record).some(([key, child]) => LABEL_KEYS.has(key) && typeof child === 'string' && (child === packageName || child.startsWith('node:')));
}

function mentions(value: unknown, packageName: string): boolean {
  if (Array.isArray(value)) {
    return value.some((item) => mentions(item, packageName));
  }
  const record = asRecord(value);
  if (record === null) {
    return false;
  }
  for (const [key, child] of Object.entries(record)) {
    if ((key === 'image' || key === 'command' || key === 'args') && textHit(child, packageName)) {
      return true;
    }
    if (key === 'labels' && labelHit(child, packageName)) {
      return true;
    }
    if (mentions(child, packageName)) {
      return true;
    }
  }
  return false;
}

function podSpec(doc: Record<string, unknown>): Record<string, unknown> | null {
  const spec = asRecord(doc.spec);
  return asRecord(asRecord(spec?.template)?.spec) ?? spec;
}

function containers(doc: Record<string, unknown>): Record<string, unknown>[] {
  const list = podSpec(doc)?.containers;
  if (!Array.isArray(list)) {
    return [];
  }
  return list.map(asRecord).filter((item): item is Record<string, unknown> => item !== null);
}

function rootFindings(container: Record<string, unknown>, file: string): PhaseFinding[] {
  const security = asRecord(container.securityContext);
  if (security === null) {
    return [];
  }
  if (security.runAsNonRoot === true) {
    return [];
  }
  if (security.runAsUser === 0) {
    return [{ ruleId: K8S_ROOT, severity: 'high', file, line: 1, message: 'runAsUser: 0' }];
  }
  if (security.runAsUser === undefined) {
    return [{ ruleId: K8S_ROOT, severity: 'medium', file, line: 1, message: 'missing runAsNonRoot' }];
  }
  return [];
}

function containerFindings(container: Record<string, unknown>, file: string): PhaseFinding[] {
  const findings = rootFindings(container, file);
  const security = asRecord(container.securityContext);
  if (security?.privileged === true) {
    findings.push({ ruleId: K8S_PRIVILEGED, severity: 'high', file, line: 1, message: 'privileged: true' });
  }
  const limits = asRecord(asRecord(container.resources)?.limits);
  if (limits === null || limits.memory === undefined) {
    findings.push({ ruleId: K8S_MEM, severity: 'info', file, line: 1, message: 'missing memory limit' });
  }
  return findings;
}

function tokenFinding(doc: Record<string, unknown>, file: string): PhaseFinding | null {
  const spec = podSpec(doc);
  if (spec?.automountServiceAccountToken !== true) {
    return null;
  }
  const mounts = containers(doc).flatMap((container) => {
    const list = container.volumeMounts;
    if (!Array.isArray(list)) {return [];}
    const records: Record<string, unknown>[] = [];
    for (const item of list) {
      const record = asRecord(item);
      if (record !== null) {records.push(record);}
    }
    return records;
  });
  const mounted = mounts.some((mount) => {
    const path = asRecord(mount)?.mountPath;
    return typeof path === 'string' && path.includes('serviceaccount');
  });
  const command = containers(doc).map((container) => JSON.stringify(container.command ?? '')).join(' ');
  const severity = mounted && !command.includes('serviceaccount') ? 'high' : 'info';
  return { ruleId: K8S_TOKEN, severity, file, line: 1, message: 'automountServiceAccountToken' };
}

function structural(doc: Record<string, unknown>, file: string, packageName: string): PhaseFinding[] {
  if (!mentions(doc, packageName)) {
    return [];
  }
  const findings = containers(doc).flatMap((container) => containerFindings(container, file));
  const volumes = podSpec(doc)?.volumes;
  if (Array.isArray(volumes) && volumes.some((volume) => asRecord(volume)?.hostPath !== undefined)) {
    findings.push({ ruleId: K8S_HOSTPATH, severity: 'high', file, line: 1, message: 'hostPath volume' });
  }
  const token = tokenFinding(doc, file);
  if (token !== null) {
    findings.push(token);
  }
  return findings;
}

export function scanManifests(file: string, text: string, packageName: string, baseline: readonly PhaseFinding[] = []): K8sResult {
  if (!enabled()) {
    return { findings: [...baseline], events: [] };
  }
  if (text.includes('{{')) {
    const match = SECRET.exec(text);
    const secret = match === null ? [] : [{ ruleId: K8S_SECRET, severity: 'high' as const, file, line: 1, message: 'secret literal', snippet: `${match[0].slice(0, 4)}****` }];
    return { findings: [...baseline, ...secret], events: [{ kind: 'parser-failure', file, line: 1, reason: 'unrendered Helm' }] };
  }
  const findings: PhaseFinding[] = [];
  for (const doc of parseAllDocuments(text)) {
    const record = asRecord(doc.toJS() as unknown);
    if (record !== null) {
      findings.push(...structural(record, file, packageName));
    }
  }
  return { findings: [...baseline, ...findings], events: [] };
}
