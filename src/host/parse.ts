const MONTHS: Record<string, number> = {
  Jan: 0,
  Feb: 1,
  Mar: 2,
  Apr: 3,
  May: 4,
  Jun: 5,
  Jul: 6,
  Aug: 7,
  Sep: 8,
  Oct: 9,
  Nov: 10,
  Dec: 11,
};

export interface OpensshPackage {
  name: string;
  distroVersion: string;
  upstream: string;
  kind: 'dpkg' | 'rpm' | 'apk';
}

export interface UpstreamVersion {
  major: number;
  minor: number;
  p: number;
}

export type ListenExposure = 'public' | 'loopback' | 'none' | 'unknown';

export function parseUpstreamVersion(raw: string): UpstreamVersion | undefined {
  const normalized = raw.replace('_p', 'p').replace(/^\d+:/, '');
  const m = normalized.match(/^(\d+)\.(\d+)(?:p(\d+))?/);
  if (m === null) return undefined;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    p: m[3] !== undefined ? Number(m[3]) : 0,
  };
}

export function extractUpstream(distroVersion: string): string | undefined {
  const noEpoch = distroVersion.replace(/^\d+:/, '');
  const m = noEpoch.match(/^(\d+\.\d+(?:[._]?p\d+)?)/);
  if (m === null || m[1] === undefined) return undefined;
  return m[1].replace('_p', 'p');
}

function versionTuple(v: UpstreamVersion): number {
  return v.major * 10_000 + v.minor * 100 + v.p;
}

/** Upstream fallback: 8.5p1 ≤ v < 9.8p1, or v < 4.4p1 (CVE-2024-6387 / historical). */
export function isUpstreamVulnerable(distroOrUpstream: string): boolean {
  const extracted = extractUpstream(distroOrUpstream) ?? distroOrUpstream;
  const v = parseUpstreamVersion(extracted);
  if (v === undefined) return false;
  const n = versionTuple(v);
  const older = versionTuple({ major: 4, minor: 4, p: 1 });
  const intro = versionTuple({ major: 8, minor: 5, p: 1 });
  const fixed = versionTuple({ major: 9, minor: 8, p: 1 });
  return n < older || (n >= intro && n < fixed);
}

function parseNamedVersion(stdout: string, kind: OpensshPackage['kind']): OpensshPackage | undefined {
  const line = stdout
    .split('\n')
    .map((l) => l.trim())
    .find((l) => /openssh/.test(l));
  if (line === undefined) return undefined;

  if (kind === 'apk') {
    const apk = line.match(/^(openssh-server|openssh)-(.+)$/);
    if (apk === null || apk[1] === undefined || apk[2] === undefined) return undefined;
    const distroVersion = apk[2];
    const upstream = extractUpstream(distroVersion);
    if (upstream === undefined) return undefined;
    return { name: apk[1], distroVersion, upstream, kind };
  }

  const parts = line.split(/[\t ]+/);
  const name = parts[0];
  const distroVersion = parts[1];
  if (name === undefined || distroVersion === undefined) return undefined;
  if (!/^openssh(?:-server)?$/.test(name)) return undefined;
  const upstream = extractUpstream(distroVersion);
  if (upstream === undefined) return undefined;
  return { name, distroVersion, upstream, kind };
}

export function parseDpkgQuery(stdout: string): OpensshPackage | undefined {
  return parseNamedVersion(stdout, 'dpkg');
}

export function parseRpmQuery(stdout: string): OpensshPackage | undefined {
  return parseNamedVersion(stdout, 'rpm');
}

export function parseApkInfo(stdout: string): OpensshPackage | undefined {
  return parseNamedVersion(stdout, 'apk');
}

export function ecosystemFor(osRelease: string | undefined, pkg: OpensshPackage): string {
  const id = osRelease?.match(/^\s*ID\s*=\s*"?([a-z0-9]+)"?/m)?.[1];
  if (id === 'ubuntu') return 'Ubuntu';
  if (id === 'debian') return 'Debian';
  if (id === 'alpine') return 'Alpine';
  if (
    id === 'rhel' ||
    id === 'centos' ||
    id === 'fedora' ||
    id === 'rocky' ||
    id === 'almalinux' ||
    id === 'ol'
  ) {
    return 'Red Hat';
  }
  if (pkg.kind === 'apk') return 'Alpine';
  if (pkg.kind === 'rpm') return 'Red Hat';
  if (pkg.distroVersion.includes('ubuntu')) return 'Ubuntu';
  return 'Debian';
}

export function detectPaas(env: NodeJS.ProcessEnv): string | undefined {
  if (env.VERCEL) return 'Vercel';
  if (env.NETLIFY) return 'Netlify';
  if (env.AWS_LAMBDA_FUNCTION_NAME) return 'AWS Lambda';
  if (env.DYNO) return 'Heroku';
  if (env.RENDER) return 'Render';
  if (env.FLY_APP_NAME) return 'Fly.io';
  if (env.K_SERVICE) return 'Cloud Run';
  if (env.CF_INSTANCE_INDEX) return 'Cloud Foundry';
  if (env.RAILWAY_ENVIRONMENT) return 'Railway';
  if (env.PLATFORM_APPLICATION_NAME) return 'Platform.sh';
  return undefined;
}

const GRACE_RE = /^\s*(?:logingracetime)\s+(\S+)/i;
const PORT_RE = /^\s*(?:port)\s+(\d+)/i;
const LISTEN_RE = /^\s*(?:listenaddress)\s+(\S+)/i;
const INCLUDE_RE = /^\s*Include\s+(\S+)/i;

export interface SshdEffective {
  loginGraceTimeZero: boolean;
  port: number;
  listenAddresses: string[];
}

function applySshdLine(line: string, acc: SshdEffective): string | undefined {
  const trimmed = line.replace(/#.*$/, '').trim();
  if (trimmed.length === 0) return undefined;
  const grace = trimmed.match(GRACE_RE);
  if (grace?.[1] !== undefined) {
    acc.loginGraceTimeZero = /^(0+|0+[smh]?)$/i.test(grace[1]);
    return undefined;
  }
  const port = trimmed.match(PORT_RE);
  if (port?.[1] !== undefined) {
    acc.port = Number(port[1]);
    return undefined;
  }
  const listen = trimmed.match(LISTEN_RE);
  if (listen?.[1] !== undefined) {
    acc.listenAddresses.push(listen[1]);
    return undefined;
  }
  const inc = trimmed.match(INCLUDE_RE);
  return inc?.[1];
}

export function parseSshdT(text: string): SshdEffective {
  const acc: SshdEffective = { loginGraceTimeZero: false, port: 22, listenAddresses: [] };
  for (const line of text.split('\n')) applySshdLine(line, acc);
  return acc;
}

export function parseSshdConfigFiles(
  files: Record<string, string>,
  entry = '/etc/ssh/sshd_config',
  glob: (pattern: string) => string[] = (pattern) =>
    Object.keys(files).filter((p) => matchGlob(pattern, p)),
): SshdEffective {
  const acc: SshdEffective = { loginGraceTimeZero: false, port: 22, listenAddresses: [] };
  const seen = new Set<string>();

  function walk(path: string): void {
    if (seen.has(path)) return;
    seen.add(path);
    const text = files[path];
    if (text === undefined) return;
    for (const line of text.split('\n')) {
      const include = applySshdLine(line, acc);
      if (include === undefined) continue;
      for (const next of glob(include)) walk(next);
    }
  }

  walk(entry);
  return acc;
}

export function matchGlob(pattern: string, path: string): boolean {
  const re = new RegExp(
    `^${pattern.replaceAll('.', '\\.').replaceAll('*', '[^/]*')}$`,
  );
  return re.test(path);
}

function splitHostPort(token: string): { host: string; port: number } | undefined {
  if (token.startsWith('[')) {
    const end = token.indexOf(']');
    if (end < 0) return undefined;
    const host = token.slice(1, end);
    const port = Number(token.slice(end + 2));
    if (!Number.isFinite(port)) return undefined;
    return { host, port };
  }
  const idx = token.lastIndexOf(':');
  if (idx < 0) return undefined;
  const port = Number(token.slice(idx + 1));
  if (!Number.isFinite(port)) return undefined;
  return { host: token.slice(0, idx), port };
}

function isLoopbackHost(host: string): boolean {
  return host === '127.0.0.1' || host === '::1' || host === 'localhost';
}

function isWildcardHost(host: string): boolean {
  return host === '0.0.0.0' || host === '*' || host === '::' || host === '[::]' || host === '';
}

export function classifyListenHost(host: string): 'public' | 'loopback' {
  if (isLoopbackHost(host)) return 'loopback';
  return 'public';
}

export function parseSsListen(text: string, port: number): ListenExposure {
  let sawLoopback = false;
  let sawPublic = false;
  for (const line of text.split('\n')) {
    if (!/\bLISTEN\b/i.test(line)) continue;
    for (const token of line.split(/\s+/)) {
      const parsed = splitHostPort(token);
      if (parsed === undefined || parsed.port !== port) continue;
      if (isLoopbackHost(parsed.host)) sawLoopback = true;
      else sawPublic = true;
    }
  }
  if (sawPublic) return 'public';
  if (sawLoopback) return 'loopback';
  if (text.trim().length === 0) return 'unknown';
  return 'none';
}

export function exposureFromListenAddresses(addresses: readonly string[], port: number): ListenExposure {
  if (addresses.length === 0) return 'unknown';
  let sawLoopback = false;
  let sawPublic = false;
  for (const raw of addresses) {
    const parsed = splitHostPort(raw.includes(':') ? raw : `${raw}:${port}`);
    const host = parsed?.host ?? raw;
    if (isLoopbackHost(host)) sawLoopback = true;
    else if (isWildcardHost(host) || classifyListenHost(host) === 'public') sawPublic = true;
  }
  if (sawPublic) return 'public';
  if (sawLoopback) return 'loopback';
  return 'none';
}

const TIMEOUT_RE = /Timeout before authentication/i;
const IP_RE = /(\d{1,3}(?:\.\d{1,3}){3})/;
const SYSLOG_RE = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})/;

export function parseSyslogTime(line: string, now: Date): Date | undefined {
  const m = line.match(SYSLOG_RE);
  if (m === null || m[1] === undefined || m[2] === undefined || m[3] === undefined) return undefined;
  const month = MONTHS[m[1]];
  if (month === undefined) return undefined;
  const day = Number(m[2]);
  const [hh, mm, ss] = m[3].split(':').map(Number);
  let year = now.getUTCFullYear();
  let ts = Date.UTC(year, month, day, hh ?? 0, mm ?? 0, ss ?? 0);
  if (ts > now.getTime() + 60_000) {
    year -= 1;
    ts = Date.UTC(year, month, day, hh ?? 0, mm ?? 0, ss ?? 0);
  }
  return new Date(ts);
}

export function countAuthTimeouts(
  text: string,
  now: Date,
  windowMs = 24 * 60 * 60 * 1000,
): Map<string, number> {
  const counts = new Map<string, number>();
  for (const line of text.split('\n')) {
    if (!TIMEOUT_RE.test(line)) continue;
    const when = parseSyslogTime(line, now);
    if (when !== undefined && now.getTime() - when.getTime() > windowMs) continue;
    const ip = line.match(IP_RE)?.[1];
    if (ip === undefined) continue;
    counts.set(ip, (counts.get(ip) ?? 0) + 1);
  }
  return counts;
}

export function isRegreSSHionVuln(vuln: { id?: string; aliases?: string[]; summary?: string }): boolean {
  const ids = [vuln.id, ...(vuln.aliases ?? [])].filter((x): x is string => typeof x === 'string');
  if (ids.some((id) => id === 'CVE-2024-6387' || id === 'CVE-2006-5051')) return true;
  return /regresshion/i.test(vuln.summary ?? '');
}
