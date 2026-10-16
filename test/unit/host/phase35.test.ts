import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { scan } from '../../../src/core/engine.js';
import {
  collectHostSnapshot,
  countAuthTimeouts,
  createProcessHostIo,
  detectPaas,
  isUpstreamVulnerable,
  parseApkInfo,
  parseDpkgQuery,
  parseRpmQuery,
  parseSshdConfigFiles,
  parseSshdT,
  parseSsListen,
  runHostCheck,
  type HostIo,
  type HostOsvVuln,
  type HostSnapshot,
} from '../../../src/host/index.js';

const fx = join(process.cwd(), 'test', 'fixtures', 'host');
const NOW = new Date('2026-10-15T17:00:00.000Z');
const FLAG = 'FULLSHIELD_EXPERIMENTAL_HOST';

function readFx(name: string): string {
  return readFileSync(join(fx, name), 'utf8');
}

const AFFECTED: HostOsvVuln[] = (
  JSON.parse(readFx('osv-affected.json')) as { vulns: HostOsvVuln[] }
).vulns;
const PATCHED: HostOsvVuln[] = [];

const UBUNTU = 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\n';
const RHEL = 'NAME="Red Hat"\nID=rhel\nVERSION_ID="9.4"\n';
const ALPINE = 'NAME="Alpine"\nID=alpine\nVERSION_ID="3.20"\n';

function linuxSnap(over: Partial<HostSnapshot>): HostSnapshot {
  return {
    platform: 'linux',
    env: {},
    osRelease: UBUNTU,
    sshdT: readFx('sshd-T-unmitigated.txt'),
    ssLtn: readFx('ss-public.txt'),
    ...over,
  };
}

describe('Phase 35 host parsers (fixtures)', () => {
  it('parses dpkg backport / vulnerable / fixed versions', () => {
    const patched = parseDpkgQuery(readFx('dpkg-backport-patched.txt'));
    expect(patched?.distroVersion).toBe('1:8.9p1-3ubuntu0.10');
    expect(patched?.upstream).toBe('8.9p1');
    expect(isUpstreamVulnerable(patched!.upstream)).toBe(true);

    const vuln = parseDpkgQuery(readFx('dpkg-vulnerable-upstream.txt'));
    expect(vuln?.upstream).toBe('9.2p1');
    expect(isUpstreamVulnerable(vuln!.upstream)).toBe(true);

    const fixed = parseDpkgQuery(readFx('dpkg-fixed.txt'));
    expect(fixed?.upstream).toBe('9.8p1');
    expect(isUpstreamVulnerable(fixed!.upstream)).toBe(false);
  });

  it('parses rpm backport / vulnerable / fixed versions', () => {
    expect(parseRpmQuery(readFx('rpm-backport-patched.txt'))?.upstream).toBe('8.7p1');
    expect(isUpstreamVulnerable('8.7p1')).toBe(true);
    expect(parseRpmQuery(readFx('rpm-vulnerable-upstream.txt'))?.upstream).toBe('9.3p1');
    expect(parseRpmQuery(readFx('rpm-fixed.txt'))?.upstream).toBe('9.8p1');
    expect(isUpstreamVulnerable('9.8p1')).toBe(false);
  });

  it('parses apk backport / vulnerable / fixed versions', () => {
    expect(parseApkInfo(readFx('apk-backport-patched.txt'))?.upstream).toBe('9.6p1');
    expect(isUpstreamVulnerable('9.6p1')).toBe(true);
    expect(parseApkInfo(readFx('apk-vulnerable-upstream.txt'))?.upstream).toBe('9.6p1');
    expect(parseApkInfo(readFx('apk-fixed.txt'))?.upstream).toBe('9.8p1');
  });

  it('upstream fallback matches 8.5p1 ≤ v < 9.8p1 or v < 4.4p1', () => {
    expect(isUpstreamVulnerable('8.5p1')).toBe(true);
    expect(isUpstreamVulnerable('8.4p1')).toBe(false);
    expect(isUpstreamVulnerable('4.3p2')).toBe(true);
    expect(isUpstreamVulnerable('4.4p1')).toBe(false);
    expect(isUpstreamVulnerable('9.7p1')).toBe(true);
    expect(isUpstreamVulnerable('9.8p1')).toBe(false);
    expect(isUpstreamVulnerable('9.8p2')).toBe(false);
    expect(isUpstreamVulnerable('1:9.2p1-1')).toBe(true);
  });

  it('parses sshd -T with and without logingracetime 0', () => {
    expect(parseSshdT(readFx('sshd-T-mitigated.txt')).loginGraceTimeZero).toBe(true);
    expect(parseSshdT(readFx('sshd-T-unmitigated.txt')).loginGraceTimeZero).toBe(false);
    expect(parseSshdT(readFx('sshd-T-unmitigated.txt')).port).toBe(22);
  });

  it('parses sshd_config Include files for LoginGraceTime 0', () => {
    const files = {
      '/etc/ssh/sshd_config': readFx('sshd_config-mitigated'),
      '/etc/ssh/sshd_config.d/50-hardening.conf': readFx('sshd_config.d-hardening.conf'),
    };
    expect(parseSshdConfigFiles(files).loginGraceTimeZero).toBe(true);
    expect(parseSshdConfigFiles({ '/etc/ssh/sshd_config': readFx('sshd_config-unmitigated') }).loginGraceTimeZero).toBe(
      false,
    );
  });

  it('classifies ss -ltn public vs loopback', () => {
    expect(parseSsListen(readFx('ss-public.txt'), 22)).toBe('public');
    expect(parseSsListen(readFx('ss-loopback.txt'), 22)).toBe('loopback');
  });

  it('detects common PaaS environment variables', () => {
    expect(detectPaas({ DYNO: 'web.1' })).toBe('Heroku');
    expect(detectPaas({ AWS_LAMBDA_FUNCTION_NAME: 'fn' })).toBe('AWS Lambda');
    expect(detectPaas({ NETLIFY: 'true' })).toBe('Netlify');
    expect(detectPaas({ RENDER: 'true' })).toBe('Render');
    expect(detectPaas({ FLY_APP_NAME: 'app' })).toBe('Fly.io');
    expect(detectPaas({ K_SERVICE: 'svc' })).toBe('Cloud Run');
    expect(detectPaas({ CF_INSTANCE_INDEX: '0' })).toBe('Cloud Foundry');
    expect(detectPaas({ RAILWAY_ENVIRONMENT: 'prod' })).toBe('Railway');
    expect(detectPaas({ PLATFORM_APPLICATION_NAME: 'app' })).toBe('Platform.sh');
    expect(detectPaas({})).toBeUndefined();
  });

  it('counts Timeout before authentication in sample auth.log within 24h', () => {
    const counts = countAuthTimeouts(readFx('auth.log'), NOW);
    expect(counts.get('203.0.113.50')).toBe(6);
    expect(counts.has('198.51.100.9')).toBe(false);
    expect(countAuthTimeouts(readFx('auth-clean.log'), NOW).size).toBe(0);
  });
});

describe('Phase 35 runHostCheck (experimental, fixtures only)', () => {
  const prev = process.env[FLAG];

  beforeEach(() => {
    process.env[FLAG] = '1';
  });

  afterEach(() => {
    if (prev === undefined) delete process.env[FLAG];
    else process.env[FLAG] = prev;
  });

  it('refuses without --experimental-host / FULLSHIELD_EXPERIMENTAL_HOST', async () => {
    delete process.env[FLAG];
    await expect(runHostCheck({ snapshot: linuxSnap({ dpkgQuery: readFx('dpkg-fixed.txt') }) })).rejects.toThrow(
      /experimental-host/,
    );
  });

  it('skips Linux without an OpenSSH package version', async () => {
    const missing = await runHostCheck({ experimental: true, snapshot: { platform: 'linux', env: {} } });
    expect(missing.skipped).toBe(true);
    expect(missing.reason).toMatch(/not installed/);
    const noVer = await runHostCheck({
      experimental: true,
      snapshot: { platform: 'linux', env: {}, sshdPresent: true },
    });
    expect(noVer.skipped).toBe(true);
    expect(noVer.reason).toMatch(/package version/);
  });

  it('skips macOS, Windows, PaaS, and containers without sshd', async () => {
    const mac = await runHostCheck({ experimental: true, snapshot: { platform: 'darwin', env: {} } });
    expect(mac.skipped).toBe(true);
    expect(mac.reason).toMatch(/macOS/i);
    expect(mac.findings).toEqual([]);
    const win = await runHostCheck({ experimental: true, snapshot: { platform: 'win32', env: {} } });
    expect(win.skipped).toBe(true);
    expect(win.reason).toMatch(/Windows/i);
    const paas = await runHostCheck({
      experimental: true,
      snapshot: { platform: 'linux', env: { VERCEL: '1' } },
    });
    expect(paas.skipped).toBe(true);
    expect(paas.reason).toMatch(/PaaS|Vercel/);
    const ctr = await runHostCheck({
      experimental: true,
      snapshot: { platform: 'linux', env: {}, container: true },
    });
    expect(ctr.skipped).toBe(true);
    expect(ctr.reason).toMatch(/container without sshd/);
  });

  it('does not flag a dpkg backport that OSV reports as patched', async () => {
    const result = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({ dpkgQuery: readFx('dpkg-backport-patched.txt') }),
      osvLookup: () => Promise.resolve(PATCHED),
    });
    expect(result.skipped).toBe(false);
    expect(result.findings.map((f) => f.ruleId)).not.toContain('HOST-SSH-001');
    expect(result.findings.map((f) => f.ruleId)).not.toContain('HOST-SSH-002');
  });

  it('flags HOST-SSH-001 for a dpkg version OSV still marks affected', async () => {
    const result = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        dpkgQuery: readFx('dpkg-vulnerable-upstream.txt'),
        sshdT: readFx('sshd-T-mitigated.txt'),
      }),
      osvLookup: () => Promise.resolve(AFFECTED),
    });
    expect(result.findings.map((f) => f.ruleId)).toContain('HOST-SSH-001');
    expect(result.findings.map((f) => f.ruleId)).not.toContain('HOST-SSH-002');
    expect(result.findings.find((f) => f.ruleId === 'HOST-SSH-001')?.message).toMatch(/vulnerable, mitigated/);
  });

  it('uses the upstream fallback when OSV is unavailable', async () => {
    const result = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({ dpkgQuery: readFx('dpkg-vulnerable-upstream.txt') }),
      osvLookup: () => Promise.reject(new Error('network down')),
    });
    expect(result.findings.map((f) => f.ruleId)).toContain('HOST-SSH-001');
    expect(result.findings.find((f) => f.ruleId === 'HOST-SSH-001')?.message).toMatch(/upstream version fallback/);
  });

  it('does not flag a dpkg version at or after 9.8p1', async () => {
    const result = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({ dpkgQuery: readFx('dpkg-fixed.txt') }),
      osvLookup: () => Promise.reject(new Error('unused')),
    });
    expect(result.findings.map((f) => f.ruleId)).not.toContain('HOST-SSH-001');
  });

  it('handles rpm patched backport, vulnerable upstream, and fixed', async () => {
    const patched = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        osRelease: RHEL,
        dpkgQuery: undefined,
        rpmQuery: readFx('rpm-backport-patched.txt'),
      }),
      osvLookup: () => Promise.resolve(PATCHED),
    });
    expect(patched.findings.map((f) => f.ruleId)).not.toContain('HOST-SSH-001');

    const vuln = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        osRelease: RHEL,
        dpkgQuery: undefined,
        rpmQuery: readFx('rpm-vulnerable-upstream.txt'),
      }),
      osvLookup: () => Promise.resolve(AFFECTED),
    });
    expect(vuln.findings.map((f) => f.ruleId)).toContain('HOST-SSH-001');

    const fixed = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        osRelease: RHEL,
        dpkgQuery: undefined,
        rpmQuery: readFx('rpm-fixed.txt'),
      }),
      osvLookup: () => Promise.resolve(PATCHED),
    });
    expect(fixed.findings.map((f) => f.ruleId)).not.toContain('HOST-SSH-001');
  });

  it('handles apk patched backport, vulnerable upstream, and fixed', async () => {
    const patched = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        osRelease: ALPINE,
        dpkgQuery: undefined,
        apkInfo: readFx('apk-backport-patched.txt'),
      }),
      osvLookup: () => Promise.resolve(PATCHED),
    });
    expect(patched.findings.map((f) => f.ruleId)).not.toContain('HOST-SSH-001');

    const vuln = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        osRelease: ALPINE,
        dpkgQuery: undefined,
        apkInfo: readFx('apk-vulnerable-upstream.txt'),
      }),
      osvLookup: () => Promise.resolve(AFFECTED),
    });
    expect(vuln.findings.map((f) => f.ruleId)).toContain('HOST-SSH-001');

    const fixed = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        osRelease: ALPINE,
        dpkgQuery: undefined,
        apkInfo: readFx('apk-fixed.txt'),
      }),
      osvLookup: () => Promise.resolve(PATCHED),
    });
    expect(fixed.findings.map((f) => f.ruleId)).not.toContain('HOST-SSH-001');
  });

  it('emits HOST-SSH-002 only when vulnerable and logingracetime is not 0', async () => {
    const unmitigated = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        dpkgQuery: readFx('dpkg-vulnerable-upstream.txt'),
        sshdT: readFx('sshd-T-unmitigated.txt'),
        ssLtn: readFx('ss-loopback.txt'),
      }),
      osvLookup: () => Promise.resolve(AFFECTED),
    });
    expect(unmitigated.findings.map((f) => f.ruleId)).toEqual(expect.arrayContaining(['HOST-SSH-001', 'HOST-SSH-002']));
    expect(unmitigated.findings.find((f) => f.ruleId === 'HOST-SSH-001')?.severity).not.toBe('critical');

    const mitigated = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        dpkgQuery: readFx('dpkg-vulnerable-upstream.txt'),
        sshdT: readFx('sshd-T-mitigated.txt'),
      }),
      osvLookup: () => Promise.resolve(AFFECTED),
    });
    expect(mitigated.findings.map((f) => f.ruleId)).not.toContain('HOST-SSH-002');
  });

  it('parses sshd_config when sshd -T is unavailable', async () => {
    const result = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        dpkgQuery: readFx('dpkg-vulnerable-upstream.txt'),
        sshdT: undefined,
        sshdConfigFiles: { '/etc/ssh/sshd_config': readFx('sshd_config-unmitigated') },
      }),
      osvLookup: () => Promise.resolve(AFFECTED),
    });
    expect(result.findings.map((f) => f.ruleId)).toContain('HOST-SSH-002');
  });

  it('sets critical only for vulnerable + unmitigated + publicly listening', async () => {
    const critical = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        dpkgQuery: readFx('dpkg-vulnerable-upstream.txt'),
        sshdT: readFx('sshd-T-unmitigated.txt'),
        ssLtn: readFx('ss-public.txt'),
      }),
      osvLookup: () => Promise.resolve(AFFECTED),
    });
    expect(critical.findings.find((f) => f.ruleId === 'HOST-SSH-001')?.severity).toBe('critical');
    expect(critical.findings.find((f) => f.ruleId === 'HOST-SSH-002')?.severity).toBe('critical');

    const loopback = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        dpkgQuery: readFx('dpkg-vulnerable-upstream.txt'),
        sshdT: readFx('sshd-T-unmitigated.txt'),
        ssLtn: readFx('ss-loopback.txt'),
      }),
      osvLookup: () => Promise.resolve(AFFECTED),
    });
    expect(loopback.findings.some((f) => f.severity === 'critical')).toBe(false);
  });

  it('emits HOST-SSH-003 for sample auth.log and not for the clean log', async () => {
    const noisy = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        dpkgQuery: readFx('dpkg-fixed.txt'),
        authLog: readFx('auth.log'),
      }),
      now: NOW,
      osvLookup: () => Promise.resolve(PATCHED),
    });
    const attempt = noisy.findings.find((f) => f.ruleId === 'HOST-SSH-003');
    expect(attempt).toBeDefined();
    expect(attempt?.message).toMatch(/possible exploitation attempts/i);
    expect(attempt?.message).not.toMatch(/confirmed attack/i);
    expect(attempt?.severity).not.toBe('critical');
    expect(attempt?.remediation).toMatch(/fail2ban/);
    expect(attempt?.remediation).toMatch(/CrowdSec/);

    const clean = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        dpkgQuery: readFx('dpkg-fixed.txt'),
        authLog: readFx('auth-clean.log'),
      }),
      now: NOW,
      osvLookup: () => Promise.resolve(PATCHED),
    });
    expect(clean.findings.map((f) => f.ruleId)).not.toContain('HOST-SSH-003');
  });

  it('remediation mentions upgrade, LoginGraceTime 0 DoS, and fail2ban/CrowdSec', async () => {
    const result = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        dpkgQuery: readFx('dpkg-vulnerable-upstream.txt'),
        authLog: readFx('auth.log'),
      }),
      now: NOW,
      osvLookup: () => Promise.resolve(AFFECTED),
    });
    const blob = result.findings.map((f) => `${f.remediation} ${f.message}`).join('\n');
    expect(blob).toMatch(/openssh-server/);
    expect(blob).toMatch(/LoginGraceTime 0/);
    expect(blob).toMatch(/DoS/);
    expect(blob).toMatch(/fail2ban/);
    expect(blob).toMatch(/CrowdSec/);
    expect(blob).not.toMatch(/sudo/);
    expect(blob).not.toMatch(/iptables|firewall-cmd|ufw /i);
  });

  it('collectHostSnapshot never invokes ssh -V or sudo', () => {
    const commands: string[][] = [];
    const io: HostIo = {
      platform: 'linux',
      env: {},
      spawn(command, args) {
        commands.push([command, ...args]);
        if (command === 'dpkg-query') {
          return { status: 0, stdout: readFx('dpkg-fixed.txt'), stderr: '' };
        }
        if (command === 'sshd' && args[0] === '-T') {
          return { status: 0, stdout: readFx('sshd-T-mitigated.txt'), stderr: '' };
        }
        if (command === 'ss') {
          return { status: 0, stdout: readFx('ss-loopback.txt'), stderr: '' };
        }
        return { status: 1, stdout: '', stderr: '' };
      },
      readFile: () => undefined,
      exists: () => false,
      glob: () => [],
    };
    const snap = collectHostSnapshot(io);
    expect(snap.dpkgQuery).toContain('openssh-server');
    expect(commands.some((c) => c[0] === 'ssh' || c.includes('-V'))).toBe(false);
    expect(commands.some((c) => c[0] === 'sudo' || c.includes('sudo'))).toBe(false);
    expect(createProcessHostIo().platform).toBe(process.platform);
    const live = createProcessHostIo();
    expect(live.spawn('sudo', ['sshd', '-T']).status).toBe(1);
    expect(live.spawn('ssh', ['-V']).status).toBe(1);
    expect(live.exists(fx)).toBe(true);
    expect(live.readFile(join(fx, 'auth.log'))).toMatch(/Timeout before authentication/);
    expect(live.glob(join(fx, 'dpkg-*.txt')).length).toBe(3);
    expect(live.readFile(join(fx, 'missing-file'))).toBeUndefined();
  });

  it('uses fetchImpl OSV JSON and falls back on HTTP failure or --offline', async () => {
    const patched = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({ dpkgQuery: readFx('dpkg-backport-patched.txt') }),
      fetchImpl: () => Promise.resolve(new Response(JSON.stringify({ vulns: [] }), { status: 200 })),
    });
    expect(patched.findings.map((f) => f.ruleId)).not.toContain('HOST-SSH-001');

    const affected = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({ dpkgQuery: readFx('dpkg-vulnerable-upstream.txt') }),
      fetchImpl: () => Promise.resolve(new Response(readFx('osv-affected.json'), { status: 200 })),
    });
    expect(affected.findings.map((f) => f.ruleId)).toContain('HOST-SSH-001');

    const failed = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({ dpkgQuery: readFx('dpkg-vulnerable-upstream.txt') }),
      fetchImpl: () => Promise.resolve(new Response('nope', { status: 500 })),
    });
    expect(failed.findings.map((f) => f.ruleId)).toContain('HOST-SSH-001');

    const offline = await runHostCheck({
      experimental: true,
      offline: true,
      snapshot: linuxSnap({ dpkgQuery: readFx('dpkg-vulnerable-upstream.txt') }),
    });
    expect(offline.findings.map((f) => f.ruleId)).toContain('HOST-SSH-001');
  });

  it('reads journalctl Timeout lines when auth.log is absent', async () => {
    const result = await runHostCheck({
      experimental: true,
      snapshot: linuxSnap({
        dpkgQuery: readFx('dpkg-fixed.txt'),
        authLog: undefined,
        journalctl: readFx('auth.log'),
      }),
      now: NOW,
      osvLookup: () => Promise.resolve(PATCHED),
    });
    expect(result.findings.map((f) => f.ruleId)).toContain('HOST-SSH-003');
  });

  it('collectHostSnapshot records rpm/apk, includes, and container markers', () => {
    const files: Record<string, string> = {
      '/etc/os-release': RHEL,
      '/etc/ssh/sshd_config': readFx('sshd_config-mitigated'),
      '/etc/ssh/sshd_config.d/50-hardening.conf': readFx('sshd_config.d-hardening.conf'),
      '/proc/1/cgroup': '1:name=systemd:/docker/abc\n',
    };
    const io: HostIo = {
      platform: 'linux',
      env: { container: 'docker' },
      spawn(command, args) {
        if (command === 'rpm' && args.includes('openssh-server')) {
          return { status: 0, stdout: readFx('rpm-fixed.txt'), stderr: '' };
        }
        if (command === 'apk' && args.includes('openssh-server')) {
          return { status: 0, stdout: readFx('apk-fixed.txt'), stderr: '' };
        }
        return { status: 1, stdout: '', stderr: '' };
      },
      readFile: (path) => files[path],
      exists: (path) => path === '/.dockerenv' || path in files,
      glob: (pattern) =>
        pattern.includes('sshd_config.d') ? ['/etc/ssh/sshd_config.d/50-hardening.conf'] : [],
    };
    const snap = collectHostSnapshot(io);
    expect(snap.rpmQuery).toContain('openssh-server');
    expect(snap.container).toBe(true);
    expect(snap.sshdConfigFiles?.['/etc/ssh/sshd_config.d/50-hardening.conf']).toMatch(/LoginGraceTime 0/);
  });
});

describe('Phase 35 default scan is unchanged', () => {
  it('does not attach host checks to scan()', async () => {
    const clean = await scan({
      cwd: join(process.cwd(), 'test', 'fixtures', 'clean-app'),
      modules: ['config'],
      offline: true,
    });
    expect(clean.findings.some((f) => f.ruleId.startsWith('HOST-'))).toBe(false);
  });
});
