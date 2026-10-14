import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { makeFindingId, type Finding } from '../core/finding.js';

const REGISTRY_HOST = 'registry.npmjs.org';
const INSTALL_SCRIPT_KEYS = ['preinstall', 'install', 'postinstall'] as const;

export function assertRegistryUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('supply: registry URL must be https://registry.npmjs.org/...');
  }
  if (parsed.protocol !== 'https:' || parsed.hostname !== REGISTRY_HOST) {
    throw new Error(`supply: only ${REGISTRY_HOST} is allowed (got ${parsed.hostname || url})`);
  }
}

export function packageNameFromSpec(spec: string): string {
  if (spec.startsWith('@')) {
    const slash = spec.indexOf('/');
    if (slash < 0) return spec;
    const scope = spec.slice(0, slash);
    const rest = spec.slice(slash + 1);
    const name = rest.includes('@') ? rest.slice(0, rest.indexOf('@')) : rest;
    return `${scope}/${name}`;
  }
  const at = spec.indexOf('@');
  return at > 0 ? spec.slice(0, at) : spec;
}

function finding(
  ruleId: string,
  title: string,
  message: string,
  file?: string,
  severity: Finding['severity'] = 'high',
): Finding {
  return {
    id: makeFindingId(ruleId, file, message),
    ruleId,
    module: 'deps',
    title,
    severity,
    confidence: 'high',
    file,
    message,
    remediation: 'Do not install this package until the behavior is reviewed. Use --ignore-scripts.',
  };
}

function walkJs(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') continue;
      walkJs(full, out);
    } else if (entry.isFile() && /\.(js|cjs|mjs|ts)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
}

function installScriptKeys(scripts: Record<string, string> | undefined): string[] {
  if (!scripts) return [];
  return INSTALL_SCRIPT_KEYS.filter((k) => typeof scripts[k] === 'string');
}

/** Static only. Never executes, installs, or runs package scripts. */
export function analyzePackageDir(dir: string): Finding[] {
  const findings: Finding[] = [];
  const manifestPath = join(dir, 'package.json');
  if (!existsSync(manifestPath) || !statSync(manifestPath).isFile()) return findings;
  const pkg = readJson(manifestPath);
  const scripts = (pkg.scripts ?? {}) as Record<string, string>;
  const keys = installScriptKeys(scripts);
  if (keys.length > 0) {
    findings.push(
      finding(
        'SUPPLY-INSTALLSCRIPT-001',
        'Package declares an install script',
        `install scripts: ${keys.join(', ')}`,
        'package.json',
      ),
    );
  }
  const sources = walkJs(dir).map((file) => ({
    file: relative(dir, file) || file,
    text: readFileSync(file, 'utf8'),
  }));
  const readsNpmrc = sources.some((s) => s.text.includes('.npmrc') || s.text.includes('.ssh'));
  const hasNet = sources.some((s) => /https\.request|http\.request|fetch\s*\(|axios\./.test(s.text));
  if (readsNpmrc && hasNet) {
    const hit = sources.find((s) => s.text.includes('.npmrc') || s.text.includes('.ssh'));
    findings.push(
      finding(
        'SUPPLY-NPMRC-NET-001',
        'Install-time code reads npm/ssh credentials and uses the network',
        'static: credential file read combined with http(s)/fetch',
        hit?.file,
        'critical',
      ),
    );
  }
  for (const src of sources) {
    if (/eval\s*\(\s*(Buffer|atob|fromCharCode|decodeURIComponent)/.test(src.text)) {
      findings.push(
        finding(
          'SUPPLY-OBFUSCATE-001',
          'Package evals a decoded/obfuscated string',
          'static: eval of decoded payload',
          src.file,
        ),
      );
    }
  }
  return findings;
}

export function diffPackageVersions(oldDir: string, newDir: string): Finding[] {
  const oldManifest = existsSync(join(oldDir, 'package.json')) ? readJson(join(oldDir, 'package.json')) : {};
  const nextManifest = existsSync(join(newDir, 'package.json')) ? readJson(join(newDir, 'package.json')) : {};
  const oldScripts = (oldManifest.scripts ?? {}) as Record<string, string>;
  const nextScripts = (nextManifest.scripts ?? {}) as Record<string, string>;
  const added = INSTALL_SCRIPT_KEYS.filter((k) => typeof nextScripts[k] === 'string' && oldScripts[k] === undefined);
  const oldSrc = walkJs(oldDir)
    .map((f) => readFileSync(f, 'utf8'))
    .join('\n');
  const newSrc = walkJs(newDir)
    .map((f) => readFileSync(f, 'utf8'))
    .join('\n');
  const newChild = /child_process/.test(newSrc) && !/child_process/.test(oldSrc);
  const newNet = /https?\.request|fetch\s*\(/.test(newSrc) && !/https?\.request|fetch\s*\(/.test(oldSrc);
  if (added.length === 0 && !newChild && !newNet) return [];
  return [
    finding(
      'SUPPLY-BEHAVIOR-001',
      'Package version adds install-script or process/network behavior',
      `added scripts=${added.join(',') || 'none'} child_process=${newChild} network=${newNet}`,
      'package.json',
    ),
  ];
}

export function checkCooldown(
  packument: { time?: Record<string, string> },
  version: string,
  minHours = 72,
  nowMs = Date.now(),
): Finding[] {
  const stamp = packument.time?.[version];
  if (!stamp) return [];
  const published = Date.parse(stamp);
  if (Number.isNaN(published)) return [];
  const ageHours = (nowMs - published) / 3_600_000;
  if (ageHours >= minHours) return [];
  return [
    finding(
      'SUPPLY-COOLDOWN-001',
      'Package version is younger than the release cooldown',
      `${version} published ${ageHours.toFixed(1)}h ago (min ${minHours}h)`,
      undefined,
      'medium',
    ),
  ];
}

export function checkLockfileIntegrity(lock: {
  packages?: Record<string, { resolved?: string; integrity?: string }>;
}): Finding[] {
  const findings: Finding[] = [];
  for (const [name, entry] of Object.entries(lock.packages ?? {})) {
    if (name === '') continue;
    const resolved = entry.resolved;
    if (!resolved) continue;
    try {
      const host = new URL(resolved).hostname;
      if (host !== REGISTRY_HOST) {
        findings.push(
          finding(
            'SUPPLY-LOCKURL-001',
            'Lockfile entry resolves from a non-npm registry host',
            `${name} resolved host ${host}`,
            'package-lock.json',
          ),
        );
      }
    } catch {
      findings.push(
        finding(
          'SUPPLY-LOCKURL-001',
          'Lockfile entry has a non-URL resolved field',
          `${name} resolved ${resolved}`,
          'package-lock.json',
        ),
      );
    }
  }
  return findings;
}

export function checkDependencyConfusion(
  pkgName: string,
  npmrc: string,
  publicExists: boolean,
): Finding[] {
  const scoped = pkgName.startsWith('@');
  const privateRegistry = /@[\w-]+\s*:\s*registry\s*=/.test(npmrc) || /registry\s*=\s*https?:\/\/(?!registry\.npmjs\.org)/.test(npmrc);
  if (scoped && privateRegistry && publicExists) {
    return [
      finding(
        'SUPPLY-CONFUSION-001',
        'Private-scope name also exists on the public registry',
        `${pkgName} is configured for a private registry but a public package exists`,
      ),
    ];
  }
  return [];
}

export function checkProvenance(previouslyHad: boolean, currentlyHas: boolean): Finding[] {
  if (previouslyHad && !currentlyHas) {
    return [
      finding(
        'SUPPLY-PROVENANCE-001',
        'Package dropped npm provenance since the last scan',
        'previous version had provenance; current version does not',
      ),
    ];
  }
  return [];
}

export interface InstallGuardOptions {
  experimental?: boolean;
  extractDir?: string;
  fetchPackument?: (url: string) => Promise<unknown>;
  runNpm?: (args: string[]) => Promise<void>;
}

export async function installGuard(
  spec: string,
  opts: InstallGuardOptions = {},
): Promise<{ findings: Finding[]; skipped?: boolean }> {
  if (!opts.experimental && process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY !== '1') {
    return { findings: [], skipped: true };
  }
  const name = packageNameFromSpec(spec);
  const url = `https://${REGISTRY_HOST}/${encodeURIComponent(name)}`;
  assertRegistryUrl(url);
  if (opts.fetchPackument) await opts.fetchPackument(url);
  const findings = opts.extractDir !== undefined ? analyzePackageDir(opts.extractDir) : [];
  if (findings.length === 0 && opts.runNpm) {
    await opts.runNpm(['install', spec, '--ignore-scripts']);
  }
  return { findings };
}
