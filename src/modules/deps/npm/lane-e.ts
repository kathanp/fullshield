import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Finding, Severity } from '../../../core/finding.js';
import {
  npmFinding,
  npmFlag,
  npmRow,
  type NpmDepthInput,
  type NpmDepthRow,
} from './types.js';

/**
 * Phases 188–207. Reads the lock `hasInstallScript` bit and, when present,
 * `cacheDir/tarballs/<encodeURIComponent(name)>.json`. Does not run scripts,
 * download tarballs, or read other lanes' findings.
 */

const TRANSITIVE = 'DEPS-SCRIPT-TRANSITIVE-001';
const OPTIONAL = 'DEPS-SCRIPT-OPTIONAL-001';
const DEV = 'DEPS-SCRIPT-DEV-001';
const PREPARE = 'DEPS-SCRIPT-PREPARE-001';
const PREPUBLISH = 'DEPS-SCRIPT-PREPUBLISH-001';
const CURL = 'DEPS-SCRIPT-CURL-001';
const BASE64 = 'DEPS-SCRIPT-BASE64-001';
const NODEGYP = 'DEPS-SCRIPT-NODEGYP-001';
const WRITE = 'DEPS-SCRIPT-WRITE-001';
const LOCK = 'DEPS-SCRIPT-LOCK-001';
const GIT = 'DEPS-SCRIPT-GIT-001';
const TOKEN = 'DEPS-SCRIPT-TOKEN-001';
const PUBLISH = 'DEPS-SCRIPT-PUBLISH-001';
const TRUSTED = 'DEPS-SCRIPT-TRUSTED-001';
const MISMATCH = 'DEPS-SCRIPT-MISMATCH-001';
const MULTI = 'DEPS-SCRIPT-MULTI-001';
const BIN = 'DEPS-SCRIPT-BIN-001';
const SHEBANG = 'DEPS-SCRIPT-SHEBANG-001';
const COND = 'DEPS-SCRIPT-COND-001';
const ROLLUP = 'DEPS-SCRIPT-ROLLUP-001';

const FLAGS = [
  'NPM_SCRIPT_TRANSITIVE',
  'NPM_SCRIPT_OPTIONAL',
  'NPM_SCRIPT_DEV',
  'NPM_SCRIPT_PREPARE',
  'NPM_SCRIPT_PREPUBLISH',
  'NPM_SCRIPT_CURL',
  'NPM_SCRIPT_BASE64',
  'NPM_SCRIPT_NODEGYP',
  'NPM_SCRIPT_WRITE',
  'NPM_SCRIPT_LOCK',
  'NPM_SCRIPT_GIT',
  'NPM_SCRIPT_TOKEN',
  'NPM_SCRIPT_PUBLISH',
  'NPM_SCRIPT_TRUSTED',
  'NPM_SCRIPT_MISMATCH',
  'NPM_SCRIPT_MULTI',
  'NPM_SCRIPT_BIN',
  'NPM_SCRIPT_SHEBANG',
  'NPM_SCRIPT_COND',
  'NPM_SCRIPT_ROLLUP',
] as const;

const SCRIPT_KEYS = [
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepublish',
  'prepublishOnly',
] as const;

type ScriptKey = (typeof SCRIPT_KEYS)[number];
type Scripts = Partial<Record<ScriptKey, string>>;

const INSTALL_KEYS: readonly ScriptKey[] = ['preinstall', 'install', 'postinstall'];
const GIT_SPEC = /^(?:git:|git\+https:|git\+ssh:|git\+http:|github:|gitlab:|bitbucket:|gist:)/i;
const PKG_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;
const ENV_PATH =
  String.raw`(?:\$(?:\{(?:HOME|USERPROFILE)\}|(?:HOME|USERPROFILE)\b)|%(?:HOME|USERPROFILE)%|\$\{process\.env\.(?:HOME|USERPROFILE)\}|process\.env\.(?:HOME|USERPROFILE)\b|process\.env\[\s*['"](?:HOME|USERPROFILE)['"]\s*\])`;
const OUTSIDE_PATH = String.raw`(?:\.\.(?:/|\\)|/|~/|${ENV_PATH})`;
const WRITE_CALL = new RegExp(
  String.raw`(?:fs\.)?(?:writeFileSync|appendFileSync|writeFile|appendFile)\s*\(\s*['"\`]?${OUTSIDE_PATH}`,
);
const WRITE_REDIRECT = new RegExp(String.raw`(?<![=-])>>?\s*['"\`]?${OUTSIDE_PATH}`);
const LOCK_NEAR =
  /(?:fs\.write|\bwrite(?:File(?:Sync)?|Sync)?\b|(?<![=-])>)[\s\S]{0,200}(?:package-lock\.json|npm-shrinkwrap\.json)|(?:package-lock\.json|npm-shrinkwrap\.json)[\s\S]{0,200}(?:fs\.write|\bwrite(?:File(?:Sync)?|Sync)?\b|(?<![=-])>)/;
const ALLOWED_SHEBANG = new Set(['node', 'sh', 'bash']);

interface Descriptor {
  scripts: Scripts;
  files: Record<string, string>;
  /** Lane D already reported DEPS-TARBALL-OBFUSC-001 for this package. */
  tarballObfuscReported: boolean;
}

interface Pkg {
  path: string;
  name: string;
  version: string;
  resolved: string;
  hasInstallScript: boolean;
  dev: boolean;
  optional: boolean;
  link: boolean;
  bin: string[];
  dependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  trustedDependencies: string[];
}

export async function laneFindings(input: NpmDepthInput): Promise<Finding[]> {
  if (!FLAGS.some((flag) => npmFlag(flag))) {return [];}
  const text = input.lockTexts['package-lock.json'];
  if (typeof text !== 'string' || text.trim() === '') {return [];}
  const parsed = parseLock(text);
  if (!parsed) {return [];}

  const { root, pkgs } = parsed;
  const directNames = new Set<string>([
    ...Object.keys(root.dependencies),
    ...Object.keys(root.optionalDependencies),
    ...Object.keys(root.devDependencies),
  ]);
  const prodNames = productionRequiredNames(root, pkgs);
  const trusted = trustedNames(root, input.manifestRaw);
  const manifest = parseManifest(input.manifestRaw);
  const descriptors = await loadDescriptors(input.cacheDir, pkgs);

  const findings: Finding[] = [];
  const ordered = [...pkgs].sort((a, b) => a.path.localeCompare(b.path));
  for (const entry of ordered) {
    if (entry.link || entry.name === '') {continue;}
    findings.push(
      ...(await packageFindings(input, entry, {
        directNames,
        prodNames,
        trusted,
        manifest,
        root,
        pkgs,
        descriptors,
      })),
    );
  }

  const withBit = ordered.filter((entry) => !entry.link && entry.hasInstallScript);
  const production = withBit.filter((entry) => isProduction(entry, prodNames));
  if (npmFlag('NPM_SCRIPT_ROLLUP') && withBit.length > 0 && production.length > 25) {
    findings.push(rollupFinding(production.length));
  }
  return findings;
}

export const laneRows: readonly NpmDepthRow[] = [
  npmRow(TRANSITIVE, 'CWE-829'),
  npmRow(OPTIONAL, 'CWE-829'),
  npmRow(DEV, 'CWE-829'),
  npmRow(PREPARE, 'CWE-829'),
  npmRow(PREPUBLISH, 'CWE-829'),
  npmRow(CURL, 'CWE-494'),
  npmRow(BASE64, 'CWE-95'),
  npmRow(NODEGYP, 'CWE-829'),
  npmRow(WRITE, 'CWE-22'),
  npmRow(LOCK, 'CWE-506'),
  npmRow(GIT, 'CWE-829'),
  npmRow(TOKEN, 'CWE-522'),
  npmRow(PUBLISH, 'CWE-506'),
  npmRow(TRUSTED, 'CWE-829'),
  npmRow(MISMATCH, 'CWE-829'),
  npmRow(MULTI, 'CWE-829'),
  npmRow(BIN, 'CWE-829'),
  npmRow(SHEBANG, 'CWE-78'),
  npmRow(COND, 'CWE-829'),
  npmRow(ROLLUP, 'CWE-829'),
];

interface PackageCtx {
  directNames: Set<string>;
  prodNames: Set<string>;
  trusted: Set<string>;
  manifest: Record<string, unknown> | undefined;
  root: Pkg;
  pkgs: Pkg[];
  descriptors: Map<string, Descriptor | undefined>;
}

async function packageFindings(
  input: NpmDepthInput,
  entry: Pkg,
  ctx: PackageCtx,
): Promise<Finding[]> {
  const out: Finding[] = [];
  const prod = isProduction(entry, ctx.prodNames);
  const direct = entry.path === `node_modules/${entry.name}` && ctx.directNames.has(entry.name);
  const optionalHit = entry.optional && entry.hasInstallScript;
  const transitiveHit = entry.hasInstallScript && prod && !direct;
  const label = entry.version === '' ? entry.name : `${entry.name}@${entry.version}`;

  if (npmFlag('NPM_SCRIPT_OPTIONAL') && optionalHit) {
    out.push(hit(
      OPTIONAL,
      'medium',
      entry.path,
      'optional hasInstallScript',
      'Optional dependency install script',
      `${label} is optional and the lock sets hasInstallScript.`,
      'Review the optional package install script before installing it.',
    ));
  } else if (npmFlag('NPM_SCRIPT_TRANSITIVE') && transitiveHit) {
    out.push(hit(
      TRANSITIVE,
      'medium',
      entry.path,
      'hasInstallScript',
      'Transitive dependency install script',
      `${label} is a transitive production dependency and the lock sets hasInstallScript.`,
      'Review the transitive install script. Direct dependencies are not this finding.',
    ));
  }

  if (npmFlag('NPM_SCRIPT_DEV') && entry.dev && entry.hasInstallScript && !ctx.prodNames.has(entry.name)) {
    out.push(hit(
      DEV,
      'info',
      entry.path,
      'dev hasInstallScript',
      'Development dependency install script',
      `${label} is a dev-only dependency and the lock sets hasInstallScript.`,
      'Dev-only install scripts do not ship in production. Confirm the package is not also required by production.',
    ));
  }

  const desc = ctx.descriptors.get(entry.name);
  const scripts = desc?.scripts ?? {};
  const joined = joinScripts(scripts);
  const split = splitGates(joined);
  const full = `${split.visible}\n${split.gated}`;

  if (npmFlag('NPM_SCRIPT_PREPARE')) {
    const prepare = scripts.prepare?.trim() ?? '';
    if (prepare !== '') {
      const git = isGitDep(entry, ctx);
      out.push(hit(
        PREPARE,
        git ? 'high' : 'medium',
        entry.path,
        'prepare',
        'Dependency prepare script',
        `${label} sets scripts.prepare. prepare runs on local npm install for git dependencies.`,
        'Read the prepare script before installing. Git dependencies run it on npm install.',
      ));
    }
  }

  if (npmFlag('NPM_SCRIPT_PREPUBLISH')) {
    const prepublish = scripts.prepublish?.trim() ?? '';
    const only = scripts.prepublishOnly?.trim() ?? '';
    if (prepublish !== '') {
      out.push(hit(
        PREPUBLISH,
        'high',
        entry.path,
        'prepublish',
        'Dependency prepublish script',
        `${label} sets scripts.prepublish. Old npm runs prepublish on install. The script key is prepublish.`,
        'Remove prepublish or replace it with prepublishOnly, which current npm does not run on install.',
      ));
    } else if (only !== '') {
      out.push(hit(
        PREPUBLISH,
        'medium',
        entry.path,
        'prepublishOnly',
        'Dependency prepublishOnly script',
        `${label} sets scripts.prepublishOnly. The script key is prepublishOnly.`,
        'Confirm prepublishOnly only runs for a publish you intend.',
      ));
    }
  }

  const patternHits: Array<{
    id: string;
    flag: string;
    severity: Severity;
    title: string;
    detail: string;
    message: string;
    remediation: string;
    match: (text: string) => boolean;
    suppress: boolean;
  }> = [
    {
      id: CURL,
      flag: 'NPM_SCRIPT_CURL',
      severity: 'critical',
      title: 'Lifecycle script pipes a download to a shell',
      detail: 'curl|sh',
      message: `${label} lifecycle script runs curl or wget and pipes it to sh, bash, or node.`,
      remediation: 'Do not install the package. A download piped to a shell is remote code execution.',
      match: hasCurlPipe,
      suppress: false,
    },
    {
      id: BASE64,
      flag: 'NPM_SCRIPT_BASE64',
      severity: 'high',
      title: 'Lifecycle script decodes base64 into eval',
      detail: 'base64 eval',
      message: `${label} passes a base64 literal of 32 or more characters to eval, Function, or spawn.`,
      remediation: 'Do not install the package. Treat decode-and-eval in an install script as malicious.',
      match: hasBase64Eval,
      suppress: desc?.tarballObfuscReported === true,
    },
    {
      id: WRITE,
      flag: 'NPM_SCRIPT_WRITE',
      severity: 'high',
      title: 'Lifecycle script writes outside the package',
      detail: 'write outside',
      message: `${label} lifecycle script writes a path that starts with .., /, ~/, or a home-directory variable.`,
      remediation: 'Do not install the package until the write target is inside the package directory.',
      match: writesOutside,
      suppress: false,
    },
    {
      id: LOCK,
      flag: 'NPM_SCRIPT_LOCK',
      severity: 'high',
      title: 'Lifecycle script writes the lockfile',
      detail: 'lockfile write',
      message: `${label} lifecycle script mentions package-lock.json or npm-shrinkwrap.json next to a write.`,
      remediation: 'Do not install a package that rewrites the lockfile during install.',
      match: writesLock,
      suppress: false,
    },
    {
      id: GIT,
      flag: 'NPM_SCRIPT_GIT',
      severity: 'high',
      title: 'Lifecycle script invokes git',
      detail: 'git',
      message: `${label} lifecycle script contains a git command or .git/hooks.`,
      remediation: 'Do not install a package whose install script invokes git or installs hooks.',
      match: touchesGit,
      suppress: false,
    },
    {
      id: TOKEN,
      flag: 'NPM_SCRIPT_TOKEN',
      severity: 'critical',
      title: 'Lifecycle script reads an npm token',
      detail: 'npm token',
      message: `${label} lifecycle script references NPM_TOKEN, NODE_AUTH_TOKEN, or npm_config__auth.`,
      remediation: 'Do not install the package. Rotate npm tokens on machines that already installed it.',
      match: hasToken,
      suppress: false,
    },
    {
      id: PUBLISH,
      flag: 'NPM_SCRIPT_PUBLISH',
      severity: 'high',
      title: 'Lifecycle script publishes',
      detail: 'npm publish',
      message: `${label} lifecycle script contains npm publish or npm whoami.`,
      remediation: 'Do not install a package whose install script publishes or queries the npm identity.',
      match: hasPublish,
      suppress: wormCombination(full),
    },
  ];

  let conditional = false;
  for (const pattern of patternHits) {
    const visible = pattern.match(split.visible);
    const gated = pattern.match(split.gated);
    if (visible) {
      if (npmFlag(pattern.flag) && !pattern.suppress) {
        out.push(hit(
          pattern.id,
          pattern.severity,
          entry.path,
          pattern.detail,
          pattern.title,
          pattern.message,
          pattern.remediation,
        ));
      }
    } else if (gated) {
      conditional = true;
    }
  }

  if (conditional && npmFlag('NPM_SCRIPT_COND')) {
    out.push(hit(
      COND,
      'medium',
      entry.path,
      'conditional lifecycle',
      'Lifecycle script hides behavior behind CI or NODE_ENV',
      `${label} branches on process.env.CI or NODE_ENV, and the non-CI or production branch contains a dangerous install pattern.`,
      'Read both branches. A check for CI or production does not make the other branch safe.',
    ));
  }

  if (npmFlag('NPM_SCRIPT_TRUSTED') && ctx.trusted.has(entry.name) && trustedDanger(full)) {
    out.push(hit(
      TRUSTED,
      'medium',
      entry.path,
      'trusted',
      'Trusted dependency has a dangerous lifecycle script',
      `${label} is listed in trustedDependencies and its lifecycle script still matches a dangerous install pattern. The trust list does not clear that pattern.`,
      'Remove the package from trustedDependencies until the script is safe, or drop the dependency.',
    ));
  }

  if (npmFlag('NPM_SCRIPT_MISMATCH') && entry.hasInstallScript && desc && !hasInstallKey(scripts)) {
    out.push(hit(
      MISMATCH,
      'medium',
      entry.path,
      'hasInstallScript mismatch',
      'Install-script flag disagrees with scripts',
      `${label} lock hasInstallScript is true, and the cached scripts object has no preinstall, install, or postinstall key.`,
      'Refresh the cached tarball manifest. Do not treat the lock bit as proof of which script runs.',
    ));
  }

  const installCount = INSTALL_KEYS.filter((key) => (scripts[key]?.trim() ?? '') !== '').length;
  if (npmFlag('NPM_SCRIPT_MULTI') && desc && installCount >= 2) {
    out.push(hit(
      MULTI,
      'info',
      entry.path,
      'multiple lifecycle scripts',
      'Package has several lifecycle scripts',
      `${label} sets ${installCount} of preinstall, install, and postinstall.`,
      'Read each lifecycle script. Several hooks are an inventory signal, not by themselves a compromise.',
    ));
  }

  if (npmFlag('NPM_SCRIPT_BIN') && desc && binIsInstall(entry.bin, scripts)) {
    out.push(hit(
      BIN,
      'medium',
      entry.path,
      'bin install',
      'Bin path is the install script',
      `${label} bin target is the same path as scripts.install or scripts.preinstall.`,
      'Confirm the executable you run is not the package install script.',
    ));
  }

  if (npmFlag('NPM_SCRIPT_NODEGYP')) {
    const gyp = await bindingText(input, entry.name, desc);
    if (gyp !== undefined) {
      const hosts = foreignHosts(gyp);
      const host = hosts[0];
      if (host !== undefined) {
        out.push(hit(
          NODEGYP,
          'medium',
          entry.path,
          host,
          'binding.gyp fetches a non-registry URL',
          `${label} binding.gyp contains a URL whose host is ${host}, not registry.npmjs.org.`,
          'Do not compile the package. Review the binding.gyp URL before any node-gyp rebuild.',
        ));
      }
    }
  }

  if (npmFlag('NPM_SCRIPT_SHEBANG') && desc) {
    const bad = await badShebang(input, entry.name, scripts, desc);
    if (bad !== undefined) {
      out.push(hit(
        SHEBANG,
        'medium',
        entry.path,
        bad,
        'Install script shebang is not node or a shell',
        `${label} install script starts with a shebang for ${bad}, which is not node, sh, or bash.`,
        'Do not run the install script. A foreign interpreter in the shebang is code execution.',
      ));
    }
  }

  return out;
}

function rollupFinding(count: number): Finding {
  return hit(
    ROLLUP,
    'info',
    'package-lock.json',
    `count ${count}`,
    'Many production packages have install scripts',
    `${count} production packages have hasInstallScript set. The threshold is 25 and is not a vulnerability count.`,
    'Review the install scripts. Per-package rows stay on the transitive install-script rule.',
  );
}

function hit(
  ruleId: string,
  severity: Severity,
  lockPath: string,
  detail: string,
  title: string,
  message: string,
  remediation: string,
): Finding {
  return npmFinding(ruleId, severity, 'package-lock.json', `${lockPath}: ${detail}`, title, message, remediation);
}

function isProduction(entry: Pkg, prodNames: Set<string>): boolean {
  if (entry.dev !== true) {return true;}
  return prodNames.has(entry.name);
}

function productionRequiredNames(root: Pkg, pkgs: readonly Pkg[]): Set<string> {
  const names = new Set<string>();
  const sources: Pkg[] = [root, ...pkgs];
  for (const pkg of sources) {
    if (pkg.path !== '' && pkg.dev) {continue;}
    for (const name of [...Object.keys(pkg.dependencies), ...Object.keys(pkg.optionalDependencies)]) {
      names.add(name);
    }
  }
  return names;
}

function isGitDep(entry: Pkg, ctx: PackageCtx): boolean {
  if (GIT_SPEC.test(entry.resolved) || GIT_SPEC.test(entry.version)) {return true;}
  for (const pkg of [ctx.root, ...ctx.pkgs]) {
    const spec = pkg.dependencies[entry.name]
      ?? pkg.optionalDependencies[entry.name]
      ?? pkg.devDependencies[entry.name];
    if (spec !== undefined && GIT_SPEC.test(spec)) {return true;}
  }
  if (ctx.manifest) {
    for (const field of ['dependencies', 'optionalDependencies', 'devDependencies']) {
      const spec = stringMap(ctx.manifest[field])?.[entry.name];
      if (spec !== undefined && GIT_SPEC.test(spec)) {return true;}
    }
  }
  return false;
}

function joinScripts(scripts: Scripts): string {
  return SCRIPT_KEYS.map((key) => scripts[key]?.trim() ?? '').filter((value) => value !== '').join('\n');
}

function hasInstallKey(scripts: Scripts): boolean {
  return INSTALL_KEYS.some((key) => scripts[key] !== undefined);
}

function hasCurlPipe(text: string): boolean {
  return /\b(?:curl|wget)\b/.test(text) && /\|\s*(?:sudo\s+)?(?:\S+\/)?(?:sh|bash|node)\b/.test(text);
}

function hasBase64Eval(text: string): boolean {
  const call = /\b(?:eval|Function|spawn)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = call.exec(text))) {
    const open = match.index + match[0].length - 1;
    const close = findMatching(text, open, '(', ')');
    if (close < 0) {continue;}
    const args = text.slice(open, close + 1);
    if (/['"`][A-Za-z0-9+/]{32,}={0,2}['"`]/.test(args)) {return true;}
  }
  return false;
}

function writesOutside(text: string): boolean {
  return WRITE_CALL.test(text) || WRITE_REDIRECT.test(text);
}

function writesLock(text: string): boolean {
  return LOCK_NEAR.test(text);
}

function touchesGit(text: string): boolean {
  return /\bgit\s/.test(text) || text.includes('.git/hooks');
}

function hasToken(text: string): boolean {
  return /\bNPM_TOKEN\b/.test(text) || /\bNODE_AUTH_TOKEN\b/.test(text) || text.includes('npm_config__auth');
}

function hasPublish(text: string): boolean {
  return /\bnpm\s+publish\b/.test(text) || /\bnpm\s+whoami\b/.test(text);
}

/** SUPPLY-WORM-001's own flag and combination. This lane does not emit that id. */
function wormCombination(text: string): boolean {
  if (!npmFlag('VEX')) {return false;}
  const token = /(?:~\/)?\.npmrc\b|\bNPM_TOKEN\b|\bGITHUB_TOKEN\b/;
  const publish = /\bnpm\s+publish\b|\bnpmPublish\b|\blibnpmpublish\b/;
  return token.test(text) && publish.test(text);
}

function trustedDanger(text: string): boolean {
  return hasCurlPipe(text) || writesOutside(text) || writesLock(text) || touchesGit(text) || hasToken(text) || hasPublish(text);
}

function binIsInstall(bins: readonly string[], scripts: Scripts): boolean {
  const targets = new Set(bins.map(normPath));
  for (const key of ['install', 'preinstall'] as const) {
    const script = scripts[key];
    if (script === undefined) {continue;}
    const path = commandPath(script);
    if (path !== undefined && targets.has(path)) {return true;}
  }
  return false;
}

function commandPath(script: string): string | undefined {
  let text = script.trim();
  if (/^node\s+/.test(text)) {text = text.replace(/^node\s+/, '');}
  const token = text.split(/\s+/)[0];
  if (token === undefined || token === '') {return undefined;}
  return normPath(token);
}

function normPath(value: string): string {
  let text = value.replace(/\\/g, '/').trim();
  while (text.startsWith('./')) {text = text.slice(2);}
  return text;
}

function foreignHosts(text: string): string[] {
  const hosts: string[] = [];
  for (const match of text.matchAll(/https?:\/\/[^\s"'<>]+/g)) {
    const raw = match[0]?.replace(/[),.;]+$/u, '');
    if (raw === undefined) {continue;}
    try {
      const host = new URL(raw).hostname;
      if (host !== 'registry.npmjs.org') {hosts.push(host);}
    } catch {
      // ignore strings that only look like URLs
    }
  }
  return hosts;
}

async function bindingText(
  input: NpmDepthInput,
  name: string,
  desc: Descriptor | undefined,
): Promise<string | undefined> {
  const cached = desc?.files['binding.gyp'] ?? desc?.files['package/binding.gyp'];
  if (cached !== undefined) {return cached;}
  return readPackageFile(input.cwd, name, 'binding.gyp');
}

async function badShebang(
  input: NpmDepthInput,
  name: string,
  scripts: Scripts,
  desc: Descriptor,
): Promise<string | undefined> {
  for (const key of ['install', 'preinstall'] as const) {
    const script = scripts[key];
    if (script === undefined) {continue;}
    const rel = commandPath(script);
    if (rel === undefined || rel.startsWith('/') || rel.includes('..')) {continue;}
    const cached = desc.files[rel] ?? desc.files[`package/${rel}`];
    const text = cached ?? await readPackageFile(input.cwd, name, rel);
    if (text === undefined) {continue;}
    const line = text.split(/\r?\n/, 1)[0] ?? '';
    const interp = shebangInterpreter(line);
    if (interp !== undefined && !ALLOWED_SHEBANG.has(interp)) {return interp;}
  }
  return undefined;
}

function shebangInterpreter(line: string): string | undefined {
  if (!line.startsWith('#!')) {return undefined;}
  const parts = line.slice(2).trim().split(/\s+/).filter((part) => part !== '');
  const first = parts[0];
  if (first === undefined) {return undefined;}
  if (first === 'env' || first.endsWith('/env')) {
    return parts.slice(1).find((part) => !part.startsWith('-'));
  }
  return first.split('/').pop();
}

async function readPackageFile(cwd: string, name: string, rel: string): Promise<string | undefined> {
  const nameParts = safeName(name);
  const relParts = safeRel(rel);
  if (nameParts === undefined || relParts === undefined) {return undefined;}
  try {
    return await readFile(join(cwd, 'node_modules', ...nameParts, ...relParts), 'utf8');
  } catch {
    return undefined;
  }
}

function safeName(name: string): string[] | undefined {
  if (!PKG_NAME.test(name)) {return undefined;}
  return name.split('/');
}

function safeRel(rel: string): string[] | undefined {
  const norm = rel.replace(/\\/g, '/');
  if (norm.startsWith('/') || norm.includes('\0')) {return undefined;}
  const parts = norm.split('/').filter((part) => part !== '');
  if (parts.length === 0 || parts.some((part) => part === '..' || part === '.')) {return undefined;}
  return parts;
}

async function loadDescriptors(
  cacheDir: string,
  pkgs: readonly Pkg[],
): Promise<Map<string, Descriptor | undefined>> {
  const out = new Map<string, Descriptor | undefined>();
  if (cacheDir.trim() === '') {return out;}
  const scriptFlags = [
    'NPM_SCRIPT_PREPARE',
    'NPM_SCRIPT_PREPUBLISH',
    'NPM_SCRIPT_CURL',
    'NPM_SCRIPT_BASE64',
    'NPM_SCRIPT_NODEGYP',
    'NPM_SCRIPT_WRITE',
    'NPM_SCRIPT_LOCK',
    'NPM_SCRIPT_GIT',
    'NPM_SCRIPT_TOKEN',
    'NPM_SCRIPT_PUBLISH',
    'NPM_SCRIPT_TRUSTED',
    'NPM_SCRIPT_MISMATCH',
    'NPM_SCRIPT_MULTI',
    'NPM_SCRIPT_BIN',
    'NPM_SCRIPT_SHEBANG',
    'NPM_SCRIPT_COND',
  ];
  if (!scriptFlags.some((flag) => npmFlag(flag))) {return out;}
  const names = [...new Set(pkgs.map((pkg) => pkg.name).filter((name) => name !== ''))];
  await Promise.all(names.map(async (name) => {
    out.set(name, await readDescriptor(cacheDir, name));
  }));
  return out;
}

async function readDescriptor(cacheDir: string, name: string): Promise<Descriptor | undefined> {
  let text: string;
  try {
    text = await readFile(join(cacheDir, 'tarballs', `${encodeURIComponent(name)}.json`), 'utf8');
  } catch {
    return undefined;
  }
  try {
    return parseDescriptor(JSON.parse(text) as unknown);
  } catch {
    return undefined;
  }
}

function parseDescriptor(value: unknown): Descriptor | undefined {
  if (!isRecord(value)) {return undefined;}
  const scripts: Scripts = {};
  if (isRecord(value.scripts)) {
    for (const key of SCRIPT_KEYS) {
      const script = value.scripts[key];
      if (typeof script === 'string') {scripts[key] = script;}
    }
  }
  const files: Record<string, string> = {};
  if (isRecord(value.files)) {
    for (const [key, file] of Object.entries(value.files)) {
      if (typeof file === 'string') {files[key] = file;}
    }
  }
  return { scripts, files, tarballObfuscReported: value.tarballObfuscReported === true };
}

function trustedNames(root: Pkg, manifestRaw: string | undefined): Set<string> {
  const names = new Set<string>(root.trustedDependencies);
  const manifest = parseManifest(manifestRaw);
  for (const item of stringList(manifest?.trustedDependencies)) {names.add(item);}
  return names;
}

function parseManifest(raw: string | undefined): Record<string, unknown> | undefined {
  if (raw === undefined || raw.trim() === '') {return undefined;}
  try {
    const value = JSON.parse(raw) as unknown;
    return isRecord(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function parseLock(text: string): { root: Pkg; pkgs: Pkg[] } | undefined {
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
  if (!isRecord(value) || !isRecord(value.packages)) {return undefined;}
  const rootRaw = value.packages[''];
  const root = parsePkg('', isRecord(rootRaw) ? rootRaw : {});
  const pkgs: Pkg[] = [];
  for (const [path, raw] of Object.entries(value.packages)) {
    if (path === '' || !isRecord(raw)) {continue;}
    const name = packageName(path);
    if (name === undefined) {continue;}
    const pkg = parsePkg(path, raw);
    pkg.name = name;
    pkgs.push(pkg);
  }
  return { root, pkgs };
}

function parsePkg(path: string, raw: Record<string, unknown>): Pkg {
  return {
    path,
    name: typeof raw.name === 'string' ? raw.name : '',
    version: typeof raw.version === 'string' ? raw.version : '',
    resolved: typeof raw.resolved === 'string' ? raw.resolved : '',
    hasInstallScript: raw.hasInstallScript === true,
    dev: raw.dev === true,
    optional: raw.optional === true,
    link: raw.link === true,
    bin: binPaths(raw.bin),
    dependencies: stringMap(raw.dependencies) ?? {},
    optionalDependencies: stringMap(raw.optionalDependencies) ?? {},
    devDependencies: stringMap(raw.devDependencies) ?? {},
    trustedDependencies: stringList(raw.trustedDependencies),
  };
}

function packageName(lockPath: string): string | undefined {
  const parts = lockPath.split('node_modules/');
  const last = parts[parts.length - 1];
  if (last === undefined || last === '' || last.endsWith('/')) {return undefined;}
  return PKG_NAME.test(last) ? last : undefined;
}

function binPaths(value: unknown): string[] {
  if (typeof value === 'string') {return [value];}
  const map = stringMap(value);
  if (map === undefined) {return [];}
  return Object.values(map);
}

function stringMap(value: unknown): Record<string, string> | undefined {
  if (!isRecord(value)) {return undefined;}
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === 'string') {out[key] = item;}
  }
  return out;
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) {return [];}
  return value.filter((item): item is string => typeof item === 'string');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

interface Split {
  visible: string;
  gated: string;
}

function splitGates(text: string): Split {
  const re = /\bif\s*\(/g;
  let visible = '';
  let gated = '';
  let cursor = 0;
  let guard = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text))) {
    guard += 1;
    if (guard > 1000) {break;}
    if (match.index < cursor) {continue;}
    const open = match.index + match[0].length - 1;
    const close = findMatching(text, open, '(', ')');
    if (close < 0) {continue;}
    const side = gateSide(text.slice(open + 1, close));
    if (side === undefined) {continue;}
    let index = skipWs(text, close + 1);
    const thenBlock = readBlock(text, index);
    if (thenBlock === undefined) {continue;}
    index = skipWs(text, thenBlock.end);
    let elseBlock: { end: number; body: string } | undefined;
    if (/^else(?:\s|\{|\()/.test(text.slice(index))) {
      index = skipWs(text, index + 4);
      elseBlock = readBlock(text, index);
    }
    const thenSplit = splitGates(thenBlock.body);
    const elseSplit = splitGates(elseBlock?.body ?? '');
    const gatedBody = side === 'then' ? thenSplit : elseSplit;
    const keepBody = side === 'then' ? elseSplit : thenSplit;
    visible += text.slice(cursor, match.index) + keepBody.visible;
    gated += gatedBody.visible + gatedBody.gated + keepBody.gated;
    const end = elseBlock?.end ?? thenBlock.end;
    cursor = end;
    re.lastIndex = end;
  }
  visible += text.slice(cursor);
  return { visible, gated };
}

function gateSide(cond: string): 'then' | 'else' | undefined {
  if (mentionsCi(cond)) {return ciNegated(cond) ? 'then' : 'else';}
  if (!/NODE_ENV/.test(cond)) {return undefined;}
  if (/NODE_ENV\s*(?:===|==)\s*['"]production['"]/.test(cond)) {return 'then';}
  if (/['"]production['"]\s*(?:===|==)\s*[^;\n]{0,80}NODE_ENV/.test(cond)) {return 'then';}
  if (/NODE_ENV\s*(?:!==|!=)\s*['"]production['"]/.test(cond)) {return 'else';}
  return undefined;
}

function mentionsCi(cond: string): boolean {
  return /process\.env\.CI\b/.test(cond) || /process\.env\[\s*['"]CI['"]\s*\]/.test(cond);
}

function ciNegated(cond: string): boolean {
  if (/!\s*(?:process\.env\.CI\b|process\.env\[\s*['"]CI['"]\s*\])/.test(cond)) {return true;}
  if (/process\.env\.CI\s*(?:===|==)\s*(?:false|0|null|undefined)\b/.test(cond)) {return true;}
  if (/process\.env\.CI\s*(?:===|==)\s*['"](?:false|)['"]/.test(cond)) {return true;}
  if (/process\.env\.CI\s*(?:!==|!=)\s*['"]true['"]/.test(cond)) {return true;}
  return false;
}

function skipWs(text: string, index: number): number {
  let cursor = index;
  while (cursor < text.length && /\s/.test(text[cursor] ?? '')) {cursor += 1;}
  return cursor;
}

function readBlock(text: string, index: number): { end: number; body: string } | undefined {
  if (text[index] !== '{') {return undefined;}
  const close = findMatching(text, index, '{', '}');
  if (close < 0) {return undefined;}
  return { end: close + 1, body: text.slice(index + 1, close) };
}

function findMatching(text: string, openIndex: number, open: string, close: string): number {
  if (text[openIndex] !== open) {return -1;}
  let depth = 0;
  let quote: string | undefined;
  for (let i = openIndex; i < text.length; i += 1) {
    const ch = text[i];
    if (quote !== undefined) {
      if (ch === '\\') {i += 1; continue;}
      if (ch === quote) {quote = undefined;}
      continue;
    }
    if (ch === '"' || ch === '\'' || ch === '`') {quote = ch; continue;}
    if (ch === open) {depth += 1;}
    else if (ch === close) {
      depth -= 1;
      if (depth === 0) {return i;}
    }
  }
  return -1;
}
