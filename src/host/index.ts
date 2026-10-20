import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { makeFindingId, type Finding, type Severity } from '../core/finding.js';
import {
  countAuthTimeouts,
  detectPaas,
  ecosystemFor,
  exposureFromListenAddresses,
  isRegreSSHionVuln,
  isUpstreamVulnerable,
  parseApkInfo,
  parseDpkgQuery,
  parseRpmQuery,
  parseSshdConfigFiles,
  parseSshdT,
  parseSsListen,
  type ListenExposure,
  type OpensshPackage,
  type SshdEffective,
} from './parse.js';

export {
  countAuthTimeouts,
  detectPaas,
  ecosystemFor,
  exposureFromListenAddresses,
  extractUpstream,
  isUpstreamVulnerable,
  parseApkInfo,
  parseDpkgQuery,
  parseRpmQuery,
  parseSshdConfigFiles,
  parseSshdT,
  parseSsListen,
  parseUpstreamVersion,
} from './parse.js';

export const DEFAULT_ATTEMPT_THRESHOLD = 5;

const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';

const REMEDIATION_UPGRADE =
  'Upgrade openssh-server via the distro package manager (apt, dnf/yum, or apk). FullShield does not auto-patch OS packages.';
const REMEDIATION_GRACE =
  'Temporary mitigation: set LoginGraceTime 0 in sshd_config and reload sshd. Note: LoginGraceTime 0 enables a connection-exhaustion DoS. FullShield does not change sshd configuration.';
const REMEDIATION_BLOCK =
  'For blocking attempts, use fail2ban or CrowdSec. FullShield does not install firewall rules, block IPs, or harden sshd.';

export interface HostIo {
  platform: string;
  env: NodeJS.ProcessEnv;
  spawn(command: string, args: readonly string[]): { status: number; stdout: string; stderr: string };
  readFile(path: string): string | undefined;
  exists(path: string): boolean;
  glob(pattern: string): string[];
}

export interface HostSnapshot {
  platform: string;
  env?: NodeJS.ProcessEnv;
  osRelease?: string;
  dpkgQuery?: string;
  rpmQuery?: string;
  apkInfo?: string;
  sshdT?: string;
  sshdConfigFiles?: Record<string, string>;
  ssLtn?: string;
  authLog?: string;
  journalctl?: string;
  container?: boolean;
  sshdPresent?: boolean;
}

export interface HostOsvVuln {
  id?: string;
  aliases?: string[];
  summary?: string;
}

export type HostOsvVerdict = 'vulnerable' | 'patched' | 'unknown';

export interface HostCheckOptions {
  experimental?: boolean;
  snapshot?: HostSnapshot;
  io?: HostIo;
  now?: Date;
  attemptThreshold?: number;
  offline?: boolean;
  fetchImpl?: (input: string | URL, init?: RequestInit) => Promise<Response>;
  osvLookup?: (query: {
    ecosystem: string;
    name: string;
    version: string;
  }) => Promise<HostOsvVuln[]>;
}

export interface HostCheckResult {
  skipped: boolean;
  reason?: string;
  findings: Finding[];
  package?: OpensshPackage;
  exposure?: ListenExposure;
  mitigated?: boolean;
  versionVulnerable?: boolean;
}

function skip(reason: string): HostCheckResult {
  return { skipped: true, reason, findings: [] };
}

export function createProcessHostIo(): HostIo {
  return {
    platform: process.platform,
    env: process.env,
    spawn(command, args) {
      if (command === 'sudo' || command === 'ssh' || args[0] === 'sudo') {
        return { status: 1, stdout: '', stderr: '' };
      }
      try {
        const result = spawnSync(command, [...args], {
          encoding: 'utf8',
          timeout: 8000,
          env: process.env,
        });
        return {
          status: result.status ?? 1,
          stdout: result.stdout ?? '',
          stderr: result.stderr ?? '',
        };
      } catch {
        return { status: 1, stdout: '', stderr: '' };
      }
    },
    readFile(path) {
      try {
        return readFileSync(path, 'utf8');
      } catch {
        return undefined;
      }
    },
    exists(path) {
      try {
        return existsSync(path);
      } catch {
        return false;
      }
    },
    glob(pattern) {
      if (!pattern.includes('*')) {return existsSync(pattern) ? [pattern] : [];}
      const slash = Math.max(pattern.lastIndexOf('/'), pattern.lastIndexOf('\\'));
      const dir = slash === -1 ? '.' : pattern.slice(0, slash);
      const filePat = slash === -1 ? pattern : pattern.slice(slash + 1);
      const re = new RegExp(`^${filePat.replaceAll('.', '\\.').replaceAll('*', '.*')}$`);
      try {
        return readdirSync(dir)
          .filter((name) => re.test(name))
          .map((name) => join(dir, name));
      } catch {
        return [];
      }
    },
  };
}

function spawnOut(io: HostIo, command: string, args: readonly string[]): string | undefined {
  const result = io.spawn(command, args);
  if (result.status !== 0) {return undefined;}
  const text = result.stdout.trim();
  return text.length > 0 ? result.stdout : undefined;
}

export function collectHostSnapshot(io: HostIo): HostSnapshot {
  const dpkgQuery =
    spawnOut(io, 'dpkg-query', ['-W', '-f=${Package}\t${Version}\n', 'openssh-server']) ??
    spawnOut(io, 'dpkg-query', ['-W', '-f=${Package}\t${Version}\n', 'openssh']);
  const rpmQuery =
    spawnOut(io, 'rpm', ['-q', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n', 'openssh-server']) ??
    spawnOut(io, 'rpm', ['-q', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n', 'openssh']);
  const apkInfo =
    spawnOut(io, 'apk', ['info', '-v', 'openssh-server']) ??
    spawnOut(io, 'apk', ['info', '-v', 'openssh']) ??
    spawnOut(io, 'apk', ['info', 'openssh-server']);
  const sshdT = spawnOut(io, 'sshd', ['-T']);
  const ssLtn = spawnOut(io, 'ss', ['-ltn']);
  const journalctl = spawnOut(io, 'journalctl', [
    '-u',
    'ssh*',
    '--since',
    '24 hours ago',
    '--no-pager',
  ]);

  const sshdConfigFiles: Record<string, string> = {};
  const mainCfg = io.readFile('/etc/ssh/sshd_config');
  if (mainCfg !== undefined) {
    sshdConfigFiles['/etc/ssh/sshd_config'] = mainCfg;
    for (const line of mainCfg.split('\n')) {
      const inc = line.replace(/#.*$/, '').trim().match(/^Include\s+(\S+)/i);
      if (inc?.[1] === undefined) {continue;}
      for (const path of io.glob(inc[1])) {
        const text = io.readFile(path);
        if (text !== undefined) {sshdConfigFiles[path] = text;}
      }
    }
  }

  const cgroup = io.readFile('/proc/1/cgroup') ?? '';
  const container =
    io.exists('/.dockerenv') ||
    io.exists('/run/.containerenv') ||
    Boolean(io.env.container) ||
    /docker|lxc|containerd|kubepods|podman/i.test(cgroup);

  return {
    platform: io.platform,
    env: io.env,
    osRelease: io.readFile('/etc/os-release'),
    dpkgQuery,
    rpmQuery,
    apkInfo,
    sshdT,
    sshdConfigFiles: Object.keys(sshdConfigFiles).length > 0 ? sshdConfigFiles : undefined,
    ssLtn,
    authLog: io.readFile('/var/log/auth.log') ?? io.readFile('/var/log/secure'),
    journalctl,
    container,
    sshdPresent: io.exists('/usr/sbin/sshd') || io.exists('/usr/bin/sshd'),
  };
}

function packageFromSnapshot(snapshot: HostSnapshot): OpensshPackage | undefined {
  if (snapshot.dpkgQuery) {return parseDpkgQuery(snapshot.dpkgQuery);}
  if (snapshot.rpmQuery) {return parseRpmQuery(snapshot.rpmQuery);}
  if (snapshot.apkInfo) {return parseApkInfo(snapshot.apkInfo);}
  return undefined;
}

function sshdFromSnapshot(snapshot: HostSnapshot): SshdEffective {
  if (snapshot.sshdT !== undefined && snapshot.sshdT.trim().length > 0) {
    return parseSshdT(snapshot.sshdT);
  }
  const files = snapshot.sshdConfigFiles ?? {};
  if (Object.keys(files).length > 0) {
    return parseSshdConfigFiles(files);
  }
  return { loginGraceTimeZero: false, port: 22, listenAddresses: [] };
}

function hasSshd(snapshot: HostSnapshot, pkg: OpensshPackage | undefined): boolean {
  if (pkg !== undefined) {return true;}
  if (snapshot.sshdPresent === true) {return true;}
  if (snapshot.sshdT !== undefined) {return true;}
  if (snapshot.sshdConfigFiles && Object.keys(snapshot.sshdConfigFiles).length > 0) {return true;}
  return false;
}

async function distroVerdict(
  pkg: OpensshPackage,
  ecosystem: string,
  opts: HostCheckOptions,
): Promise<HostOsvVerdict> {
  if (opts.offline === true && opts.osvLookup === undefined) {return 'unknown';}
  const names = pkg.name === 'openssh-server' ? [pkg.name, 'openssh'] : [pkg.name, 'openssh-server'];
  try {
    let sawResult = false;
    for (const name of names) {
      let vulns: HostOsvVuln[];
      if (opts.osvLookup !== undefined) {
        vulns = await opts.osvLookup({ ecosystem, name, version: pkg.distroVersion });
      } else {
        const fetchImpl = opts.fetchImpl ?? fetch;
        const response = await fetchImpl(OSV_QUERY_URL, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            package: { name, ecosystem },
            version: pkg.distroVersion,
          }),
        });
        if (!response.ok) {continue;}
        const body = (await response.json()) as { vulns?: HostOsvVuln[] };
        vulns = body.vulns ?? [];
      }
      sawResult = true;
      if (vulns.some((v) => isRegreSSHionVuln(v))) {return 'vulnerable';}
    }
    return sawResult ? 'patched' : 'unknown';
  } catch {
    return 'unknown';
  }
}

function hostFinding(
  ruleId: string,
  title: string,
  severity: Severity,
  message: string,
  remediation: string,
  file: string,
  snippet: string,
  cwe: string,
): Finding {
  return {
    id: makeFindingId(ruleId, file, snippet),
    ruleId,
    module: 'config',
    title,
    severity,
    confidence: ruleId === 'HOST-SSH-003' ? 'medium' : 'high',
    cwe,
    file,
    message,
    remediation,
    snippet,
    references: ['CVE-2024-6387', 'https://nvd.nist.gov/vuln/detail/CVE-2024-6387'],
  };
}

function versionSeverity(mitigated: boolean, exposure: ListenExposure): Severity {
  if (!mitigated && exposure === 'public') {return 'critical';}
  if (exposure === 'public') {return 'high';}
  return 'medium';
}

function mitigationSeverity(exposure: ListenExposure): Severity {
  return exposure === 'public' ? 'critical' : 'high';
}

/**
 * Experimental Linux-only OpenSSH exposure check (regreSSHion / CVE-2024-6387).
 * Detection and reporting only — never blocks, patches, or hardens OS services.
 */
export async function runHostCheck(opts: HostCheckOptions = {}): Promise<HostCheckResult> {
  if (opts.experimental !== true && process.env.FULLSHIELD_EXPERIMENTAL_HOST !== '1') {
    throw new Error('host requires --experimental-host (FULLSHIELD_EXPERIMENTAL_HOST=1)');
  }

  const io = opts.io ?? createProcessHostIo();
  const platform = opts.snapshot?.platform ?? io.platform;
  const env = opts.snapshot !== undefined ? (opts.snapshot.env ?? {}) : io.env;

  if (platform === 'darwin') {
    return skip('macOS is not supported; Linux only.');
  }
  if (platform === 'win32') {
    return skip('Windows is not supported; Linux only.');
  }

  const paas = detectPaas(env);
  if (paas !== undefined) {
    return skip(`PaaS environment (${paas}).`);
  }

  const snapshot = opts.snapshot ?? collectHostSnapshot(io);
  const pkg = packageFromSnapshot(snapshot);

  if (snapshot.container === true && !hasSshd(snapshot, pkg)) {
    return skip('container without sshd.');
  }
  if (!hasSshd(snapshot, pkg)) {
    return skip('openssh-server not installed.');
  }
  if (pkg === undefined) {
    return skip('could not read an OpenSSH package version (dpkg-query / rpm / apk).');
  }

  const sshd = sshdFromSnapshot(snapshot);
  const fromSs =
    snapshot.ssLtn !== undefined ? parseSsListen(snapshot.ssLtn, sshd.port) : 'unknown';
  const fromCfg = exposureFromListenAddresses(sshd.listenAddresses, sshd.port);
  const exposure: ListenExposure =
    fromSs === 'public' || fromSs === 'loopback' || fromSs === 'none' ? fromSs : fromCfg;

  const osv = await distroVerdict(pkg, ecosystemFor(snapshot.osRelease, pkg), opts);
  const versionVulnerable = osv === 'vulnerable' || (osv === 'unknown' && isUpstreamVulnerable(pkg.upstream));
  const mitigated = sshd.loginGraceTimeZero;

  const findings: Finding[] = [];
  const file = '/etc/ssh/sshd_config';

  if (versionVulnerable) {
    const state = mitigated ? 'vulnerable, mitigated' : 'vulnerable, unmitigated';
    findings.push(
      hostFinding(
        'HOST-SSH-001',
        'OpenSSH version is in the CVE-2024-6387 (regreSSHion) range',
        versionSeverity(mitigated, exposure),
        `openssh-server ${pkg.distroVersion} (upstream ${pkg.upstream}) is ${state}. Source: ${osv === 'unknown' ? 'upstream version fallback (OSV unavailable)' : 'OSV distro advisory'}. FullShield does not stop OS or SSH exploits.`,
        `${REMEDIATION_UPGRADE} ${REMEDIATION_GRACE}`,
        file,
        `${pkg.name} ${pkg.distroVersion}`,
        'CWE-364',
      ),
    );
  }

  if (versionVulnerable && !mitigated) {
    findings.push(
      hostFinding(
        'HOST-SSH-002',
        'OpenSSH LoginGraceTime mitigation is not set',
        mitigationSeverity(exposure),
        `sshd LoginGraceTime is not 0 (${stateForGrace(sshd)}). Unmitigated CVE-2024-6387 exposure. FullShield does not change sshd configuration.`,
        `${REMEDIATION_GRACE} ${REMEDIATION_UPGRADE}`,
        file,
        'logingracetime',
        'CWE-693',
      ),
    );
  }

  const now = opts.now ?? new Date();
  const threshold = opts.attemptThreshold ?? DEFAULT_ATTEMPT_THRESHOLD;
  const logText = snapshot.journalctl ?? snapshot.authLog;
  if (logText !== undefined) {
    const counts = countAuthTimeouts(logText, now);
    const flagged = [...counts.entries()].filter(([, n]) => n > threshold);
    if (flagged.length > 0) {
      const detail = flagged.map(([ip, n]) => `${ip}×${n}`).join(', ');
      findings.push(
        hostFinding(
          'HOST-SSH-003',
          'Possible SSH authentication-timeout exploitation attempts',
          'medium',
          `possible exploitation attempts: Timeout before authentication above threshold ${threshold} in the last 24h (${detail}). Not labeled as exploitation confirmation.`,
          REMEDIATION_BLOCK,
          '/var/log/auth.log',
          detail,
          'CWE-307',
        ),
      );
    }
  }

  return {
    skipped: false,
    findings,
    package: pkg,
    exposure,
    mitigated,
    versionVulnerable,
  };
}

function stateForGrace(sshd: SshdEffective): string {
  return sshd.loginGraceTimeZero ? 'logingracetime 0' : 'logingracetime not 0';
}
