/**
 * Phase 364. Prebuilt binary download hosts.
 * Off unless FULLSHIELD_EXPERIMENTAL_BINHOST=1.
 * Parses URL literals. Does not download and does not execute gyp.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_BINHOST';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export interface BinHostFile {
  path: string;
  text: string;
}

export interface BinHostFinding {
  ruleId: 'DEPS-BINHOST-001';
  severity: 'medium';
  host: string;
  file: string;
  message: string;
}

const URL_LITERAL = /https?:\/\/[^\s"'`<>)\\]+/g;

/** Shared extractor used on gyp and node-pre-gyp text even when phase 356 is off. */
export function extractUrlHosts(text: string): string[] {
  const hosts: string[] = [];
  for (const match of text.matchAll(URL_LITERAL)) {
    const raw = match[0];
    if (raw === undefined) {
      continue;
    }
    try {
      const host = new URL(raw).host;
      if (!hosts.includes(host)) {
        hosts.push(host);
      }
    } catch {
      continue;
    }
  }
  return hosts;
}

export function binaryHosts(registryHost: string, files: readonly BinHostFile[]): BinHostFinding[] {
  if (!enabled()) {
    return [];
  }
  const findings: BinHostFinding[] = [];
  const seen = new Set<string>();
  for (const file of files) {
    for (const host of extractUrlHosts(file.text)) {
      if (host === registryHost || seen.has(host)) {
        continue;
      }
      seen.add(host);
      findings.push({
        ruleId: 'DEPS-BINHOST-001',
        severity: 'medium',
        host,
        file: file.path,
        message: `Native binary host ${host} in ${file.path} is not the package registry host. Allow it in policy if it is intended.`,
      });
    }
  }
  return findings;
}
