import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { loadConfig } from '../../core/config.js';

const MIN_NODE = [22, 13, 0] as const;
const LOCKFILES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;
const FLAGS = [
  'FULLSHIELD_EXPERIMENTAL_SAST_GAPS',
  'FULLSHIELD_EXPERIMENTAL_FRAMEWORKS',
  'FULLSHIELD_EXPERIMENTAL_CLASSES',
  'FULLSHIELD_EXPERIMENTAL_SECRETS_ADV',
  'FULLSHIELD_EXPERIMENTAL_VEX',
  'FULLSHIELD_EXPERIMENTAL_DLP',
  'FULLSHIELD_EXPERIMENTAL_MCPCFG',
  'FULLSHIELD_EXPERIMENTAL_POLICY',
  'FULLSHIELD_EXPERIMENTAL_HOST',
  'FULLSHIELD_EXPERIMENTAL_TAINT_V2',
  'FULLSHIELD_EXPERIMENTAL_CI_REPORTS',
  'FULLSHIELD_EXPERIMENTAL_DIFF',
  'FULLSHIELD_EXPERIMENTAL_LICENSE',
  'FULLSHIELD_EXPERIMENTAL_INGEST',
  'FULLSHIELD_PARSE_POOL',
] as const;

export function nodeOk(version: string): boolean {
  const parts = version.split('.').map((part) => Number(part));
  for (let i = 0; i < MIN_NODE.length; i += 1) {
    const got = parts[i] ?? 0;
    const need = MIN_NODE[i] ?? 0;
    if (got > need) {return true;}
    if (got < need) {return false;}
  }
  return true;
}

export interface DoctorOptions {
  offline?: boolean;
  config?: string;
}

/** Local environment report. Does not query OSV when `--offline` is set. */
export async function runDoctor(cwd: string, options: DoctorOptions = {}): Promise<string> {
  const lines: string[] = [];
  const version = process.versions.node;
  lines.push(`node: ${version} ${nodeOk(version) ? 'ok' : 'too old (need >= 22.13.0)'}`);
  const locks = LOCKFILES.filter((name) => existsSync(join(cwd, name)));
  lines.push(locks.length > 0 ? `lockfile: ${locks.join(', ')}` : 'lockfile: none');
  const cacheDir = join(homedir(), '.cache', 'fullshield', 'osv');
  let cacheFiles = 0;
  if (existsSync(cacheDir)) {
    cacheFiles = readdirSync(cacheDir).length;
  }
  lines.push(`cache: ${existsSync(cacheDir) ? cacheDir : 'absent'} (${cacheFiles} files)`);
  const on = FLAGS.filter((name) => process.env[name] === '1');
  lines.push(on.length > 0 ? `flags: ${on.join(', ')}` : 'flags: none');
  let profile: string | undefined;
  try {
    const config = await loadConfig(cwd, options.config);
    profile = config.profile;
    const profilePart = config.profile ? `, profile ${config.profile}` : '';
    lines.push(
      `config: valid (failOn ${config.failOn}, offline ${config.deps.offline}${profilePart})`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    lines.push(`config: invalid (${message})`);
  }
  const experimentalOn = Object.keys(process.env).filter(
    (name) => name.startsWith('FULLSHIELD_EXPERIMENTAL_') && process.env[name] === '1',
  );
  if (experimentalOn.length >= 3 && profile === undefined) {
    lines.push(
      `warning: ${experimentalOn.length} FULLSHIELD_EXPERIMENTAL_* flags are set without a config profile (set profile to recommended | ci-strict | pr-fast | prod-monitor)`,
    );
  }
  const offline = options.offline === true;
  lines.push(
    offline
      ? 'osv: network skipped (--offline); reachability uses the local lockfile only'
      : 'osv: network allowed; reachability still uses the local lockfile',
  );
  return lines.join('\n');
}
