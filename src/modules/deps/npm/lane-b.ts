import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Finding, ModuleName, Severity } from '../../../core/finding.js';
import { rangeSatisfies } from '../semver.js';
import { npmFinding, npmFlag, npmRow, type NpmDepthInput, type NpmDepthRow } from './types.js';

/**
 * Phases 128–147. Home `.npmrc` is read only from `FULLSHIELD_NPM_HOME`
 * (test hook for `scan --include-home`) or from a listed `home/.npmrc`.
 * The real user home is never opened.
 *
 * R12: a private manifest whose direct specs are only `^MAJOR.MINOR.PATCH`
 * does not get the missing-packageManager finding.
 */

const FLOAT_001 = 'DEPS-FLOAT-001';
const FLOAT_002 = 'DEPS-FLOAT-002';
const GITSPEC_001 = 'DEPS-GITSPEC-001';
const FILESPEC_001 = 'DEPS-FILESPEC-001';
const URLSPEC_001 = 'DEPS-URLSPEC-001';
const TAGSPEC_001 = 'DEPS-TAGSPEC-001';
const OVERRIDE_VULN_001 = 'DEPS-OVERRIDE-VULN-001';
const OVERRIDE_WIDE_001 = 'DEPS-OVERRIDE-WIDE-001';
const OVERRIDE_ALIAS_001 = 'DEPS-OVERRIDE-ALIAS-001';
const LIFECYCLE_001 = 'CONFIG-LIFECYCLE-001';
const NPMRC_REG_001 = 'DEPS-NPMRC-REG-001';
const NPMRC_SCRIPT_001 = 'DEPS-NPMRC-SCRIPT-001';
const NPMRC_HOME_001 = 'DEPS-NPMRC-HOME-001';
const PACKAGEMANAGER_001 = 'DEPS-PACKAGEMANAGER-001';
const PACKAGEMANAGER_002 = 'DEPS-PACKAGEMANAGER-002';
const COREPACK_001 = 'DEPS-COREPACK-001';
const ENGINES_001 = 'CONFIG-ENGINES-001';
const ENGINE_STRICT_001 = 'DEPS-ENGINE-STRICT-001';
const TRUSTED_001 = 'DEPS-TRUSTED-001';
const PUBLISHCONFIG_001 = 'DEPS-PUBLISHCONFIG-001';
const PUBLISHCONFIG_002 = 'DEPS-PUBLISHCONFIG-002';
const BIN_SHADOW_001 = 'DEPS-BIN-SHADOW-001';
const OSCPU_001 = 'DEPS-OSCPU-001';

const FLAGS = [
  'NPM_FLOAT',
  'NPM_GITSPEC',
  'NPM_FILESPEC',
  'NPM_URLSPEC',
  'NPM_TAGSPEC',
  'NPM_OVERRIDE_VULN',
  'NPM_OVERRIDE_WIDE',
  'NPM_OVERRIDE_ALIAS',
  'NPM_LIFECYCLE',
  'NPM_NPMRC_REG',
  'NPM_NPMRC_SCRIPT',
  'NPM_NPMRC_HOME',
  'NPM_PACKAGEMANAGER',
  'NPM_COREPACK',
  'NPM_ENGINES',
  'NPM_ENGINE_STRICT',
  'NPM_TRUSTED',
  'NPM_PUBLISHCONFIG',
  'NPM_BINSHADOW',
  'NPM_OSCPU',
] as const;

const DEP_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const;
const PROD_FIELDS = ['dependencies', 'optionalDependencies'] as const;
type DepField = (typeof DEP_FIELDS)[number];

const GIT_PREFIXES = ['git+https:', 'git+http:', 'git+ssh:', 'git:', 'github:', 'gitlab:', 'bitbucket:', 'gist:'];
const BARE_TAGS = new Set(['next', 'beta', 'canary']);
const LIFECYCLE_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'];
const NODE_BUILTINS = new Set(['fs', 'path', 'child_process', 'http', 'https', 'net', 'tls', 'crypto', 'os', 'dns']);
const LOCK_MANAGER: Record<string, string> = {
  'package-lock.json': 'npm',
  'npm-shrinkwrap.json': 'npm',
  'yarn.lock': 'yarn',
  'pnpm-lock.yaml': 'pnpm',
  'bun.lock': 'bun',
};
const PM_EXACT = /^(npm|pnpm|yarn|bun)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(\+sha512\..+)?$/;

export async function laneFindings(input: NpmDepthInput): Promise<Finding[]> {
  if (!FLAGS.some((name) => npmFlag(name))) {return [];}
  const findings: Finding[] = [];
  const manifest = parseManifest(input.manifestRaw);
  if (manifest !== undefined) {
    specFindings(findings, manifest);
    if (npmFlag('NPM_OVERRIDE_VULN') || npmFlag('NPM_OVERRIDE_WIDE') || npmFlag('NPM_OVERRIDE_ALIAS')) {
      await overrideFindings(findings, input, manifest);
    }
    if (npmFlag('NPM_LIFECYCLE')) {lifecycleFindings(findings, manifest);}
    if (npmFlag('NPM_PACKAGEMANAGER') || npmFlag('NPM_COREPACK')) {packageManagerFindings(findings, input, manifest);}
    if (npmFlag('NPM_ENGINES')) {await enginesFindings(findings, input, manifest);}
    if (npmFlag('NPM_PUBLISHCONFIG')) {publishConfigFindings(findings, manifest);}
    if (npmFlag('NPM_BINSHADOW')) {await binShadowFindings(findings, input, manifest);}
    if (npmFlag('NPM_OSCPU')) {osCpuFindings(findings, input, manifest);}
  }
  if (npmFlag('NPM_NPMRC_REG') || npmFlag('NPM_NPMRC_SCRIPT') || npmFlag('NPM_ENGINE_STRICT') || npmFlag('NPM_TRUSTED')) {
    await projectNpmrcFindings(findings, input, manifest);
  }
  if (npmFlag('NPM_NPMRC_HOME')) {await homeNpmrcFindings(findings, input);}
  return unique(findings);
}

export const laneRows: readonly NpmDepthRow[] = [
  npmRow(FLOAT_001, 'CWE-829'),
  npmRow(FLOAT_002, 'CWE-829'),
  npmRow(GITSPEC_001, 'CWE-829'),
  npmRow(FILESPEC_001, 'CWE-829'),
  npmRow(URLSPEC_001, 'CWE-494'),
  npmRow(TAGSPEC_001, 'CWE-829'),
  npmRow(OVERRIDE_VULN_001, 'CWE-1104'),
  npmRow(OVERRIDE_WIDE_001, 'CWE-829'),
  npmRow(OVERRIDE_ALIAS_001, 'CWE-829'),
  npmRow(LIFECYCLE_001, 'CWE-829'),
  npmRow(NPMRC_REG_001, 'CWE-494'),
  npmRow(NPMRC_SCRIPT_001, 'CWE-829'),
  npmRow(NPMRC_HOME_001, 'CWE-494'),
  npmRow(PACKAGEMANAGER_001, 'CWE-1104'),
  npmRow(PACKAGEMANAGER_002, 'CWE-1104'),
  npmRow(COREPACK_001, 'CWE-353'),
  npmRow(ENGINES_001, 'CWE-1104'),
  npmRow(ENGINE_STRICT_001, 'CWE-693'),
  npmRow(TRUSTED_001, 'CWE-829'),
  npmRow(PUBLISHCONFIG_001, 'CWE-494'),
  npmRow(PUBLISHCONFIG_002, 'CWE-668'),
  npmRow(BIN_SHADOW_001, 'CWE-427'),
  npmRow(OSCPU_001, 'CWE-1104'),
];

function specFindings(findings: Finding[], manifest: Record<string, unknown>): void {
  const wantFloat = npmFlag('NPM_FLOAT');
  const wantGit = npmFlag('NPM_GITSPEC');
  const wantFile = npmFlag('NPM_FILESPEC');
  const wantUrl = npmFlag('NPM_URLSPEC');
  const wantTag = npmFlag('NPM_TAGSPEC');
  if (!wantFloat && !wantGit && !wantFile && !wantUrl && !wantTag) {return;}
  for (const item of depSpecs(manifest, DEP_FIELDS)) {
    const kind = classifySpec(item.spec);
    const snippet = `${item.name}@${item.spec === '' ? '""' : item.spec}`;
    if (kind === 'git' && wantGit) {
      add(findings, GITSPEC_001, 'high', 'package.json', snippet,
        'Git dependency spec',
        `${item.name} is requested from a git protocol in package.json.`,
        'Replace the git spec with a registry version that has a lockfile integrity.');
    } else if (kind === 'file' && wantFile) {
      add(findings, FILESPEC_001, 'medium', 'package.json', snippet,
        'File or link dependency spec',
        `${item.name} uses a file: or link: spec in package.json.`,
        'Depend on a published registry version instead of a local path.');
    } else if (kind === 'url' && wantUrl) {
      add(findings, URLSPEC_001, 'high', 'package.json', snippet,
        'URL dependency spec',
        `${item.name} is requested from an HTTP URL whose host is not registry.npmjs.org.`,
        'Use a registry.npmjs.org tarball or a semver range.');
    } else if (kind === 'float' && wantFloat) {
      add(findings, FLOAT_001, 'medium', 'package.json', snippet,
        'Floating dependency spec',
        `${item.name} uses a floating spec (${item.spec === '' ? 'empty' : item.spec}).`,
        'Pin a semver range with an upper bound, or an exact version.');
    } else if (kind === 'unbounded' && wantFloat && isProdField(item.field)) {
      add(findings, FLOAT_002, 'low', 'package.json', snippet,
        'Dependency spec without an upper bound',
        `${item.name} allows every version above a floor (${item.spec}).`,
        'Add an upper bound or switch to a caret, tilde, or exact version.');
    } else if (kind === 'tag' && wantTag) {
      add(findings, TAGSPEC_001, 'medium', 'package.json', snippet,
        'Dist-tag dependency spec',
        `${item.name} tracks a dist-tag instead of a version.`,
        'Depend on an exact version or a bounded semver range.');
    }
  }
}

async function overrideFindings(
  findings: Finding[],
  input: NpmDepthInput,
  manifest: Record<string, unknown>,
): Promise<void> {
  for (const pin of collectOverrides(manifest)) {
    const alias = overrideAlias(pin.spec);
    if (alias !== undefined && alias.other !== pin.name && npmFlag('NPM_OVERRIDE_ALIAS')) {
      add(findings, OVERRIDE_ALIAS_001, 'high', 'package.json', `${pin.name}=>${alias.other}@${alias.version}`,
        'Override replaces a package with a different name',
        `The override for ${pin.name} installs ${alias.other}@${alias.version}.`,
        'Override to the same package name, or remove the npm: alias.');
      continue;
    }
    if (isWideOverride(pin.spec) && npmFlag('NPM_OVERRIDE_WIDE')) {
      add(findings, OVERRIDE_WIDE_001, 'medium', 'package.json', `${pin.name}@${pin.spec}`,
        'Override has no upper bound',
        `The override for ${pin.name} is ${pin.spec}.`,
        'Pin the override to an exact version or a caret range.');
      continue;
    }
    if (!npmFlag('NPM_OVERRIDE_VULN') || !isExactVersion(pin.spec)) {continue;}
    const ids = await osvIds(input.cacheDir, pin.name, pin.spec);
    if (ids === undefined || ids.length === 0) {continue;}
    for (const id of ids) {
      add(findings, OVERRIDE_VULN_001, 'high', 'package.json', `${pin.name}@${pin.spec} ${id}`,
        'Override pins a vulnerable version',
        `The override pins ${pin.name}@${pin.spec}, which OSV lists as ${id}.`,
        'Pin a version that the OSV cache does not list as affected.');
    }
  }
}

function lifecycleFindings(findings: Finding[], manifest: Record<string, unknown>): void {
  const scripts = asRecord(manifest.scripts);
  if (scripts === undefined) {return;}
  for (const name of LIFECYCLE_SCRIPTS) {
    const body = scripts[name];
    if (typeof body !== 'string' || !riskyLifecycle(body)) {continue;}
    add(findings, LIFECYCLE_001, 'high', 'package.json', `${name}: ${body.slice(0, 180)}`,
      'Lifecycle script fetches remote code',
      `The root ${name} script downloads or pipes remote content to a shell.`,
      'Remove the downloader from the lifecycle script and run a local file instead.',
      'config');
  }
}

function packageManagerFindings(
  findings: Finding[],
  input: NpmDepthInput,
  manifest: Record<string, unknown>,
): void {
  const managers = requiredManagers(listedFiles(input));
  const raw = manifest.packageManager;
  if (raw === undefined) {
    if (npmFlag('NPM_PACKAGEMANAGER') && managers.size > 0 && !privateCaretOnly(manifest)) {
      const listed = [...managers].sort().join(', ');
      add(findings, PACKAGEMANAGER_001, 'low', 'package.json', `packageManager missing (${listed})`,
        'packageManager is missing',
        `A lockfile is present (${listed}) and package.json has no packageManager field.`,
        'Set packageManager to the lockfile manager at an exact version, for example npm@10.9.2.');
    }
    return;
  }
  if (typeof raw !== 'string') {
    if (npmFlag('NPM_PACKAGEMANAGER')) {
      add(findings, PACKAGEMANAGER_002, 'medium', 'package.json', 'packageManager',
        'packageManager is not name@version',
        'packageManager is present and is not <name>@<exact semver>.',
        'Set packageManager to npm, pnpm, yarn, or bun at an exact MAJOR.MINOR.PATCH version.');
    }
    return;
  }
  const parsed = parsePackageManager(raw);
  if (npmFlag('NPM_PACKAGEMANAGER')) {
    const mismatch = parsed.exact && managers.size > 0 && [...managers].some((manager) => manager !== parsed.name);
    if (!parsed.exact || mismatch) {
      const why = mismatch
        ? `packageManager is ${raw.trim()} but the lockfile manager is ${[...managers].sort().join(', ')}.`
        : `packageManager is ${raw.trim()}, which is not <name>@<exact semver> for npm, pnpm, yarn, or bun.`;
      add(findings, PACKAGEMANAGER_002, 'medium', 'package.json', raw.trim().slice(0, 180),
        'packageManager does not match the lockfile',
        why,
        'Set packageManager to the lockfile manager at an exact version, such as npm@10.9.2.');
    }
  }
  if (npmFlag('NPM_COREPACK') && parsed.exact && !parsed.hasHash && !devEnginesHasHash(manifest)) {
    add(findings, COREPACK_001, 'info', 'package.json', raw.trim().slice(0, 180),
      'packageManager has no Corepack integrity',
      `${raw.trim()} has no +sha512. suffix and devEngines.packageManager has no hash.`,
      'Append the Corepack +sha512. hash, or set devEngines.packageManager to a hashed version. This check does not download the tarball.');
  }
}

async function enginesFindings(
  findings: Finding[],
  input: NpmDepthInput,
  manifest: Record<string, unknown>,
): Promise<void> {
  const range = enginesNode(manifest);
  for (const file of pinPaths(input.files)) {
    const text = await readRel(input.cwd, file);
    if (text === undefined) {continue;}
    const pin = pinVersion(text);
    if (pin === undefined) {continue;}
    if (range === undefined) {
      if (enginesNodeUnparseable(manifest)) {continue;}
      add(findings, ENGINES_001, 'medium', 'package.json', `${file}=${pin}`,
        'Node pin is not covered by engines.node',
        `${file} pins ${pin} and package.json has no engines.node range.`,
        'Set engines.node so it includes the pinned version.',
        'config');
      continue;
    }
    const included = rangeSatisfies(range, pin);
    if (included !== false) {continue;}
    add(findings, ENGINES_001, 'medium', 'package.json', `engines.node=${range} ${file}=${pin}`,
      'engines.node excludes the pinned Node version',
      `engines.node (${range}) does not include ${pin} from ${file}.`,
      'Widen engines.node to include the pinned version, or change the pin file.',
      'config');
  }
}

function publishConfigFindings(findings: Finding[], manifest: Record<string, unknown>): void {
  const publish = asRecord(manifest.publishConfig);
  if (manifest.private === true) {
    if (publish?.access === 'public') {
      add(findings, PUBLISHCONFIG_002, 'medium', 'package.json', 'publishConfig.access=public',
        'Private package publishes as public',
        'private is true and publishConfig.access is public.',
        'Remove publishConfig.access or set it to restricted.');
    }
    return;
  }
  const registry = publish?.registry;
  if (typeof registry !== 'string') {return;}
  const host = foreignRegistryHost(registry);
  if (host === undefined) {return;}
  add(findings, PUBLISHCONFIG_001, 'high', 'package.json', `publishConfig.registry=${host}`,
    'publishConfig registry is not the npm registry',
    `publishConfig.registry host is ${host}, and private is not true.`,
    'Publish to registry.npmjs.org, or set private to true.');
}

async function binShadowFindings(
  findings: Finding[],
  input: NpmDepthInput,
  manifest: Record<string, unknown>,
): Promise<void> {
  const rootBins = rootBinNames(manifest);
  const seen = new Set<string>();
  for (const name of directNames(manifest, DEP_FIELDS)) {
    if (seen.has(name)) {continue;}
    seen.add(name);
    const bins = await dependencyBins(input, manifest, name);
    for (const bin of bins) {
      const builtin = NODE_BUILTINS.has(bin);
      const shadowsRoot = rootBins.has(bin);
      if (!builtin && !shadowsRoot) {continue;}
      const why = builtin
        ? `${name} installs a bin named ${bin}, which is a Node builtin.`
        : `${name} installs a bin named ${bin}, which is also a bin of the root package.`;
      add(findings, BIN_SHADOW_001, 'medium', 'package.json', `${name} bin ${bin}`,
        'Dependency bin shadows another command',
        why,
        'Rename the bin so it is not a Node builtin and not a root package bin.');
    }
  }
}

function osCpuFindings(findings: Finding[], input: NpmDepthInput, manifest: Record<string, unknown>): void {
  for (const name of directNames(manifest, PROD_FIELDS)) {
    const entry = lockEntry(input.lockTexts, name);
    if (entry === undefined) {continue;}
    const reasons: string[] = [];
    if (listExcludes(entry.os, process.platform)) {reasons.push(`os excludes ${process.platform}`);}
    if (listExcludes(entry.cpu, process.arch)) {reasons.push(`cpu excludes ${process.arch}`);}
    if (reasons.length === 0) {continue;}
    add(findings, OSCPU_001, 'info', 'package-lock.json', `${name} ${reasons.join(', ')}`,
      'Locked package excludes this platform',
      `${name} is a direct production dependency and its lock entry ${reasons.join(' and ')}. The package is still sent to OSV.`,
      'Confirm the install is intentional for this os and cpu. This finding is informational.');
  }
}

async function projectNpmrcFindings(
  findings: Finding[],
  input: NpmDepthInput,
  manifest: Record<string, unknown> | undefined,
): Promise<void> {
  const files = await loadNpmrcs(input.cwd, projectNpmrcPaths(input.files));
  const range = manifest === undefined ? undefined : enginesNode(manifest);
  let scriptsIgnored = false;
  for (const rc of files) {
    for (const line of rc.lines) {
      if (npmFlag('NPM_NPMRC_REG') && isRegistryKey(line.key)) {
        const host = foreignRegistryHost(line.value);
        if (host !== undefined) {
          add(findings, NPMRC_REG_001, 'high', rc.file, `registry host ${host}`,
            'Project .npmrc registry is not the npm registry',
            `${rc.file} sets ${line.key} to host ${host}.`,
            'Point registry at https://registry.npmjs.org/ or remove the line.');
        }
      }
      if (npmFlag('NPM_NPMRC_SCRIPT') && line.key === 'ignore-scripts' && line.value.toLowerCase() === 'false') {
        add(findings, NPMRC_SCRIPT_001, 'info', rc.file, 'ignore-scripts=false',
          'Project .npmrc allows install scripts',
          `${rc.file} sets ignore-scripts=false. This is informational and does not mean the project is compromised.`,
          'Set ignore-scripts=true and list the installers you accept in trustedDependencies.');
      }
      if (line.key === 'ignore-scripts' && line.value.toLowerCase() === 'true') {scriptsIgnored = true;}
      if (
        npmFlag('NPM_ENGINE_STRICT') &&
        line.key === 'engine-strict' &&
        line.value.toLowerCase() === 'false' &&
        range !== undefined
      ) {
        add(findings, ENGINE_STRICT_001, 'info', rc.file, 'engine-strict=false',
          'engine-strict is off while engines.node is set',
          `${rc.file} sets engine-strict=false and engines.node is ${range}.`,
          'Set engine-strict=true so installs honor engines.node.');
      }
    }
  }
  if (!npmFlag('NPM_TRUSTED') || !scriptsIgnored || manifest === undefined) {return;}
  const trusted = trustedSet(manifest);
  for (const name of directNames(manifest, PROD_FIELDS)) {
    if (trusted.has(name)) {continue;}
    const entry = lockEntry(input.lockTexts, name);
    if (entry?.hasInstallScript !== true) {continue;}
    add(findings, TRUSTED_001, 'medium', 'package.json', `${name} hasInstallScript`,
      'Install script is not in trustedDependencies',
      `${name} has hasInstallScript in the lockfile, ignore-scripts=true, and the name is not in trustedDependencies.`,
      'Add the package to trustedDependencies after reviewing its install script, or remove the dependency.');
  }
}

async function homeNpmrcFindings(findings: Finding[], input: NpmDepthInput): Promise<void> {
  const sources: Array<{ file: string; text: string | undefined }> = [];
  const home = npmHomeDir();
  if (home !== undefined) {
    sources.push({ file: '~/.npmrc', text: await readAbs(join(home, '.npmrc')) });
  }
  if (input.files.includes('home/.npmrc')) {
    sources.push({ file: 'home/.npmrc', text: await readRel(input.cwd, 'home/.npmrc') });
  }
  for (const source of sources) {
    if (source.text === undefined) {continue;}
    for (const line of parseNpmrc(source.text)) {
      if (!isRegistryKey(line.key)) {continue;}
      const host = foreignRegistryHost(line.value);
      if (host === undefined) {continue;}
      add(findings, NPMRC_HOME_001, 'medium', source.file, `registry host ${host}`,
        'Home .npmrc registry is not the npm registry',
        `${source.file} sets ${line.key} to host ${host}. Token values are not printed.`,
        'Point the home registry at https://registry.npmjs.org/.');
    }
  }
}

function add(
  findings: Finding[],
  ruleId: string,
  severity: Severity,
  file: string,
  snippet: string,
  title: string,
  message: string,
  remediation: string,
  module: ModuleName = 'deps',
): void {
  findings.push(npmFinding(ruleId, severity, file, snippet, title, message, remediation, 'high', module));
}

function unique(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const finding of findings) {
    if (seen.has(finding.id)) {continue;}
    seen.add(finding.id);
    out.push(finding);
  }
  return out;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {return undefined;}
  return value as Record<string, unknown>;
}

function parseManifest(raw: string | undefined): Record<string, unknown> | undefined {
  if (raw === undefined) {return undefined;}
  try {
    return asRecord(JSON.parse(raw) as unknown);
  } catch {
    return undefined;
  }
}

interface DepSpec { field: DepField; name: string; spec: string }

function depSpecs(manifest: Record<string, unknown>, fields: readonly DepField[]): DepSpec[] {
  const out: DepSpec[] = [];
  for (const field of fields) {
    const block = asRecord(manifest[field]);
    if (block === undefined) {continue;}
    for (const [name, value] of Object.entries(block)) {
      if (typeof value !== 'string') {continue;}
      out.push({ field, name, spec: value.trim() });
    }
  }
  return out;
}

function directNames(manifest: Record<string, unknown>, fields: readonly DepField[]): string[] {
  const names: string[] = [];
  for (const field of fields) {
    const block = asRecord(manifest[field]);
    if (block === undefined) {continue;}
    for (const name of Object.keys(block)) {names.push(name);}
  }
  return names;
}

function isProdField(field: DepField): boolean {
  return (PROD_FIELDS as readonly string[]).includes(field);
}

type SpecKind = 'git' | 'file' | 'url' | 'float' | 'unbounded' | 'tag';

function classifySpec(spec: string): SpecKind | undefined {
  const lower = spec.toLowerCase();
  if (GIT_PREFIXES.some((prefix) => lower.startsWith(prefix))) {return 'git';}
  if (lower.startsWith('file:') || lower.startsWith('link:')) {return 'file';}
  if (foreignHttpUrl(spec)) {return 'url';}
  if (spec === '*' || spec === 'x' || spec === 'X' || spec === 'latest' || spec === '') {return 'float';}
  if ((spec.startsWith('>=') || spec.startsWith('>')) && !spec.includes('<')) {return 'unbounded';}
  if (BARE_TAGS.has(spec) || isNameAtTag(spec)) {return 'tag';}
  return undefined;
}

function foreignHttpUrl(spec: string): boolean {
  return foreignRegistryHost(spec) !== undefined && /^https?:\/\//i.test(spec);
}

function isNameAtTag(spec: string): boolean {
  if (spec.startsWith('npm:')) {return false;}
  const match = /^(?:@[^@/\s]+\/)?[^@/\s]+@([^@/\s]+)$/.exec(spec);
  const tag = match?.[1];
  if (tag === undefined || tag.length === 0) {return false;}
  return !/\d/.test(tag);
}

interface OverridePin { name: string; spec: string }

function collectOverrides(manifest: Record<string, unknown>): OverridePin[] {
  const pins: OverridePin[] = [];
  walkOverrides(manifest.overrides, undefined, pins);
  walkOverrides(manifest.resolutions, undefined, pins);
  const pnpm = asRecord(manifest.pnpm);
  walkOverrides(pnpm?.overrides, undefined, pins);
  return pins;
}

function walkOverrides(value: unknown, parent: string | undefined, out: OverridePin[]): void {
  if (typeof value === 'string') {
    if (parent !== undefined && parent.length > 0) {out.push({ name: parent, spec: value.trim() });}
    return;
  }
  const record = asRecord(value);
  if (record === undefined) {return;}
  for (const [key, child] of Object.entries(record)) {
    const name = key === '.' ? parent : packageNameFromOverrideKey(key);
    if (typeof child === 'string') {
      if (name !== undefined && name.length > 0) {out.push({ name, spec: child.trim() });}
    } else {
      walkOverrides(child, name ?? parent, out);
    }
  }
}

function packageNameFromOverrideKey(key: string): string | undefined {
  let name = key.trim();
  while (name.startsWith('**/')) {name = name.slice(3);}
  if (name === '' || name === '.') {return undefined;}
  if (name.startsWith('@')) {
    const slash = name.indexOf('/');
    if (slash === -1) {return undefined;}
    const at = name.indexOf('@', slash + 1);
    return at === -1 ? name : name.slice(0, at);
  }
  const at = name.indexOf('@');
  const base = at === -1 ? name : name.slice(0, at);
  return base.length > 0 ? base : undefined;
}

function overrideAlias(spec: string): { other: string; version: string } | undefined {
  const match = /^npm:(@[^@\s/]+\/[^@\s/]+|[^@\s/]+)@(.+)$/.exec(spec);
  if (match?.[1] === undefined || match[2] === undefined) {return undefined;}
  return { other: match[1], version: match[2] };
}

function isWideOverride(spec: string): boolean {
  if (spec === '*' || spec === 'latest') {return true;}
  if (spec.startsWith('>=') || spec.startsWith('>')) {return !spec.includes('<');}
  return false;
}

function isExactVersion(spec: string): boolean {
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(spec);
}

async function osvIds(cacheDir: string, name: string, version: string): Promise<string[] | undefined> {
  const text = await readAbs(join(cacheDir, 'osv', `${name.replaceAll('/', '__')}@${version}.json`));
  if (text === undefined) {return undefined;}
  try {
    const vulns = asRecord(JSON.parse(text) as unknown)?.vulns;
    if (!Array.isArray(vulns)) {return undefined;}
    const ids: string[] = [];
    for (const vuln of vulns) {
      const id = asRecord(vuln)?.id;
      if (typeof id === 'string' && id.length > 0) {ids.push(id);}
    }
    return ids;
  } catch {
    return undefined;
  }
}

function riskyLifecycle(body: string): boolean {
  if (/\bcurl\b/i.test(body) || /\bwget\b/i.test(body) || body.includes('Invoke-WebRequest')) {return true;}
  return /https?:\/\/\S+\s*\|\s*(?:sh|bash|zsh|dash|ksh|fish|pwsh|powershell|cmd)\b/i.test(body);
}

function listedFiles(input: NpmDepthInput): string[] {
  return [...new Set([...input.files, ...Object.keys(input.lockTexts)])];
}

function requiredManagers(files: readonly string[]): Set<string> {
  const managers = new Set<string>();
  for (const file of files) {
    const base = file.slice(file.lastIndexOf('/') + 1);
    const manager = LOCK_MANAGER[base];
    if (manager !== undefined) {managers.add(manager);}
  }
  return managers;
}

/** Private package whose every direct spec is a caret range. Keeps R12 at zero. */
function privateCaretOnly(manifest: Record<string, unknown>): boolean {
  if (manifest.private !== true) {return false;}
  const specs = depSpecs(manifest, DEP_FIELDS);
  if (specs.length === 0) {return false;}
  return specs.every((item) => /^\^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(item.spec));
}

function parsePackageManager(raw: string): { name: string; exact: boolean; hasHash: boolean } {
  const trimmed = raw.trim();
  const match = PM_EXACT.exec(trimmed);
  const name = match?.[1];
  if (name !== undefined) {
    return { name, exact: true, hasHash: trimmed.includes('+sha512.') };
  }
  return { name: trimmed, exact: false, hasHash: trimmed.includes('+sha512.') };
}

function devEnginesHasHash(manifest: Record<string, unknown>): boolean {
  const pm = asRecord(manifest.devEngines)?.packageManager;
  if (typeof pm === 'string') {return pm.includes('sha512.');}
  const record = asRecord(pm);
  if (record === undefined) {return false;}
  for (const key of ['version', 'hash', 'integrity']) {
    const value = record[key];
    if (typeof value === 'string' && value.includes('sha512.')) {return true;}
  }
  return false;
}

function enginesNode(manifest: Record<string, unknown>): string | undefined {
  const node = asRecord(manifest.engines)?.node;
  return typeof node === 'string' ? node.trim() : undefined;
}

function enginesNodeUnparseable(manifest: Record<string, unknown>): boolean {
  const engines = manifest.engines;
  if (engines === undefined) {return false;}
  const record = asRecord(engines);
  if (record === undefined) {return true;}
  return record.node !== undefined && typeof record.node !== 'string';
}

function pinPaths(files: readonly string[]): string[] {
  return files.filter((file) =>
    file === '.nvmrc' || file === '.node-version' || file.endsWith('/.nvmrc') || file.endsWith('/.node-version'));
}

function pinVersion(text: string): string | undefined {
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) {continue;}
    const stripped = line.replace(/^v/i, '');
    const match = /^(\d+\.\d+\.\d+)/.exec(stripped);
    return match?.[1];
  }
  return undefined;
}

function projectNpmrcPaths(files: readonly string[]): string[] {
  return files.filter((file) => file !== 'home/.npmrc' && (file === '.npmrc' || file.endsWith('/.npmrc')));
}

interface NpmrcLine { key: string; value: string }
interface ParsedNpmrc { file: string; lines: NpmrcLine[] }

async function loadNpmrcs(cwd: string, files: readonly string[]): Promise<ParsedNpmrc[]> {
  const out: ParsedNpmrc[] = [];
  for (const file of files) {
    const text = await readRel(cwd, file);
    if (text === undefined) {continue;}
    out.push({ file, lines: parseNpmrc(text) });
  }
  return out;
}

function parseNpmrc(text: string): NpmrcLine[] {
  const out: NpmrcLine[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#') || line.startsWith(';')) {continue;}
    const eq = line.indexOf('=');
    if (eq <= 0) {continue;}
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }
    out.push({ key: line.slice(0, eq).trim().toLowerCase(), value });
  }
  return out;
}

function isRegistryKey(key: string): boolean {
  return /^(@[^:]+:)?registry$/.test(key);
}

function foreignRegistryHost(raw: string): string | undefined {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {return undefined;}
  if (url.hostname === 'registry.npmjs.org') {return undefined;}
  return url.hostname;
}

function npmHomeDir(): string | undefined {
  const home = process.env.FULLSHIELD_NPM_HOME;
  if (home === undefined || home.trim() === '') {return undefined;}
  return home;
}

function trustedSet(manifest: Record<string, unknown>): Set<string> {
  const value = manifest.trustedDependencies;
  if (!Array.isArray(value)) {return new Set();}
  return new Set(value.filter((item): item is string => typeof item === 'string'));
}

function lockEntry(
  lockTexts: Readonly<Record<string, string>>,
  name: string,
): Record<string, unknown> | undefined {
  const key = `node_modules/${name}`;
  for (const text of Object.values(lockTexts)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      continue;
    }
    const root = asRecord(parsed);
    if (root === undefined) {continue;}
    const fromPackages = asRecord(asRecord(root.packages)?.[key]);
    if (fromPackages !== undefined) {return fromPackages;}
    const fromV1 = asRecord(asRecord(root.dependencies)?.[name]);
    if (fromV1 !== undefined) {return fromV1;}
  }
  return undefined;
}

function rootBinNames(manifest: Record<string, unknown>): Set<string> {
  const name = typeof manifest.name === 'string' ? manifest.name : '';
  const short = name.startsWith('@') ? name.slice(name.lastIndexOf('/') + 1) : name;
  return new Set(binNames(manifest.bin, short));
}

function binNames(bin: unknown, packageName: string): string[] {
  if (typeof bin === 'string' && bin.length > 0 && packageName.length > 0) {return [packageName];}
  const record = asRecord(bin);
  if (record === undefined) {return [];}
  return Object.keys(record);
}

async function dependencyBins(
  input: NpmDepthInput,
  manifest: Record<string, unknown>,
  name: string,
): Promise<string[]> {
  const local = await localBins(input.cwd, name);
  if (local !== undefined) {return local;}
  const entry = lockEntry(input.lockTexts, name);
  if (entry?.bin !== undefined) {return binNames(entry.bin, name);}
  const version = typeof entry?.version === 'string' ? entry.version : exactSpecVersion(specOf(manifest, name));
  if (version === undefined) {return [];}
  return (await packumentBins(input.cacheDir, name, version)) ?? [];
}

function specOf(manifest: Record<string, unknown>, name: string): string | undefined {
  for (const field of DEP_FIELDS) {
    const value = asRecord(manifest[field])?.[name];
    if (typeof value === 'string') {return value.trim();}
  }
  return undefined;
}

function exactSpecVersion(spec: string | undefined): string | undefined {
  if (spec === undefined) {return undefined;}
  return isExactVersion(spec) ? spec : undefined;
}

async function localBins(cwd: string, name: string): Promise<string[] | undefined> {
  const text = await readAbs(join(cwd, 'node_modules', ...name.split('/'), 'package.json'));
  if (text === undefined) {return undefined;}
  try {
    const record = asRecord(JSON.parse(text) as unknown);
    if (record === undefined || record.bin === undefined) {return [];}
    return binNames(record.bin, name);
  } catch {
    return [];
  }
}

async function packumentBins(cacheDir: string, name: string, version: string): Promise<string[] | undefined> {
  const text = await readAbs(join(cacheDir, 'registry', `${name.replaceAll('/', '__')}.json`));
  if (text === undefined) {return undefined;}
  try {
    const doc = asRecord(JSON.parse(text) as unknown);
    const nested = asRecord(doc?.packument);
    const body = nested ?? doc;
    const entry = asRecord(asRecord(body?.versions)?.[version]);
    if (entry === undefined || entry.bin === undefined) {return undefined;}
    return binNames(entry.bin, name);
  } catch {
    return undefined;
  }
}

function listExcludes(list: unknown, current: string): boolean {
  if (!Array.isArray(list) || list.length === 0) {return false;}
  const items: string[] = [];
  for (const item of list) {
    if (typeof item === 'string' && item.length > 0) {items.push(item);}
  }
  if (items.length === 0 || items.includes('any')) {return false;}
  const negated = items.filter((item) => item.startsWith('!'));
  if (negated.length !== 0 && negated.length !== items.length) {return false;}
  if (negated.length === items.length) {return negated.some((item) => item.slice(1) === current);}
  return !items.includes(current);
}

async function readRel(cwd: string, rel: string): Promise<string | undefined> {
  return readAbs(join(cwd, rel));
}

async function readAbs(file: string): Promise<string | undefined> {
  try {
    return await readFile(file, 'utf8');
  } catch {
    return undefined;
  }
}
