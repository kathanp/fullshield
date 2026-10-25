import { readFile } from 'node:fs/promises';
import { basename, join } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import type { Finding } from '../../core/finding.js';
import { runConfigAstChecks } from './astChecks.js';
import { electronEnabled } from '../sast/experimental.js';
import { lockUsesElectron, packageUsesElectron, scanElectronSource } from './electron.js';
import { scanDockerfile } from './dockerfile.js';
import { scanPackageScripts } from './packageJson.js';

interface ConfigBag {
  findings: Finding[];
  sources: Array<{ rel: string; text: string }>;
  usesElectron: boolean;
}

const MARKET_FLAGS = [
  'FULLSHIELD_EXPERIMENTAL_RSC',
  'FULLSHIELD_EXPERIMENTAL_COOLDOWN',
  'FULLSHIELD_EXPERIMENTAL_IMPORTIMPLANT',
  'FULLSHIELD_EXPERIMENTAL_VERINFLATE',
  'FULLSHIELD_EXPERIMENTAL_AGENTRULES',
  'FULLSHIELD_EXPERIMENTAL_AGENTSPAWN',
  'FULLSHIELD_EXPERIMENTAL_MCPPOISON',
  'FULLSHIELD_EXPERIMENTAL_VITEFS',
  'FULLSHIELD_EXPERIMENTAL_HOSTPOISON',
  'FULLSHIELD_EXPERIMENTAL_MARKUP',
  'FULLSHIELD_EXPERIMENTAL_TRUSTHOST',
] as const;

function marketOn(): boolean {
  return MARKET_FLAGS.some((flag) => process.env[flag] === '1');
}

async function addMarket(cwd: string, files: readonly string[], findings: Finding[]): Promise<void> {
  if (!marketOn()) {return;}
  const { marketFindings } = await import('../market/scan.js');
  findings.push(...(await marketFindings(cwd, files)));
}

async function addCorsReflect(findings: Finding[], sources: ReadonlyArray<{ rel: string; text: string }>): Promise<void> {
  if (process.env.FULLSHIELD_EXPERIMENTAL_CORSREFLECT !== '1') {return;}
  const { scanCorsReflect } = await import('./corsReflect.js');
  for (const source of sources) {findings.push(...(await scanCorsReflect(source.rel, source.text)));}
}

async function readText(cwd: string, rel: string): Promise<string | undefined> {
  try {
    return await readFile(join(cwd, rel), 'utf8');
  } catch {
    return undefined;
  }
}

async function readDockerfile(cwd: string, rel: string, base: string, bag: ConfigBag): Promise<boolean> {
  if (base !== 'Dockerfile' && !base.endsWith('.dockerfile')) {return false;}
  const text = await readText(cwd, rel);
  if (text !== undefined) {bag.findings.push(...scanDockerfile(rel, text));}
  return true;
}

function notePackageElectron(base: string, text: string, bag: ConfigBag): void {
  if (base === 'package.json' && packageUsesElectron(text)) {bag.usesElectron = true;}
  if (base === 'package-lock.json' && lockUsesElectron(text)) {bag.usesElectron = true;}
}

async function readPackage(cwd: string, rel: string, base: string, bag: ConfigBag): Promise<void> {
  if (base === 'package.json' || base === 'package-lock.json') {
    const text = await readText(cwd, rel);
    if (text === undefined) {return;}
    notePackageElectron(base, text, bag);
    bag.findings.push(...scanPackageScripts(rel, text));
    return;
  }
  if ((base === 'yarn.lock' || base === 'pnpm-lock.yaml') && !bag.usesElectron) {
    const text = await readText(cwd, rel);
    if (text !== undefined && lockUsesElectron(text)) {bag.usesElectron = true;}
  }
}

async function readSource(cwd: string, rel: string, bag: ConfigBag): Promise<void> {
  if (!/\.[cm]?[jt]sx?$/.test(rel)) {return;}
  const text = await readText(cwd, rel);
  if (text === undefined) {return;}
  bag.sources.push({ rel, text });
  try {
    bag.findings.push(...(await runConfigAstChecks(rel, text)));
  } catch {
    return;
  }
}

async function scanConfigFiles(cwd: string, files: readonly string[]): Promise<ConfigBag> {
  const bag: ConfigBag = { findings: [], sources: [], usesElectron: false };
  for (const rel of files) {
    const base = basename(rel);
    if (await readDockerfile(cwd, rel, base, bag)) {continue;}
    await readPackage(cwd, rel, base, bag);
    await readSource(cwd, rel, bag);
  }
  return bag;
}

function addElectron(bag: ConfigBag): void {
  if (!electronEnabled() || !bag.usesElectron) {return;}
  for (const source of bag.sources) {bag.findings.push(...scanElectronSource(source.rel, source.text));}
}

export const configModule: ScanModule = {
  name: 'config',
  async run(ctx) {
    const bag = await scanConfigFiles(ctx.cwd, ctx.files);
    addElectron(bag);
    await addCorsReflect(bag.findings, bag.sources);
    await addMarket(ctx.cwd, ctx.files, bag.findings);
    return bag.findings;
  },
};
