import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, sep } from 'node:path';

import { scan } from '../core/engine.js';
import { renderSarifReport, validateSarif21 } from '../reporters/sarif.js';

function arg(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) {return undefined;}
  return argv[index + 1];
}

export function productionCache(): string {
  return resolve(homedir(), '.cache', 'fullshield');
}

export function isProductionCache(path: string): boolean {
  const resolved = resolve(path);
  const prod = productionCache();
  return resolved === prod || resolved.startsWith(`${prod}${sep}`);
}

function collectIds(project: string): string[] {
  const dir = join(project, 'osv-cache', 'osv');
  const ids: string[] = [];
  for (const name of readdirSync(dir)) {
    const doc = JSON.parse(readFileSync(join(dir, name), 'utf8')) as { vulns?: Array<{ id?: string }> };
    for (const vuln of doc.vulns ?? []) {
      if (typeof vuln.id === 'string') {ids.push(vuln.id);}
    }
  }
  return ids;
}

function packageNames(project: string): string[] {
  const pkg = JSON.parse(readFileSync(join(project, 'package.json'), 'utf8')) as { dependencies?: Record<string, string> };
  return Object.keys(pkg.dependencies ?? {});
}

export async function drill(project: string, budgetMs: number, sarifPath: string | undefined, logPath: string): Promise<{ code: number; stdout: string; stderr: string }> {
  if (isProductionCache(project)) {
    return { code: 1, stdout: '', stderr: 'production cache path is rejected\n' };
  }
  const started = Date.now();
  const result = await scan({ cwd: project, modules: ['deps'], offline: true });
  if (Date.now() - started > budgetMs) {return { code: 1, stdout: '', stderr: 'time budget exceeded\n' };}
  const json = JSON.stringify(result);
  const ids = collectIds(project);
  for (const id of ids) {
    if (!json.includes(id)) {return { code: 1, stdout: '', stderr: 'advisory id missing from JSON\n' };}
  }
  for (const name of packageNames(project)) {
    if (!json.includes(name)) {return { code: 1, stdout: '', stderr: 'package name missing from findings\n' };}
  }
  const sarifDoc: unknown = sarifPath === undefined ? JSON.parse(renderSarifReport(result)) : JSON.parse(readFileSync(sarifPath, 'utf8'));
  const errors = validateSarif21(sarifDoc);
  if (errors.length > 0) {return { code: 1, stdout: '', stderr: `${errors.join('\n')}\n` };}
  writeFileSync(logPath, `drill unreviewed\n`);
  return { code: 0, stdout: `drill ok ${packageNames(project).join(',')}\n`, stderr: '' };
}

export async function main(argv: readonly string[]): Promise<number> {
  for (const token of argv) {
    if (token.startsWith('-')) {continue;}
    if (isProductionCache(token)) {
      process.stderr.write('production cache path is rejected\n');
      return 1;
    }
  }
  const project = arg(argv, '--project');
  const logPath = arg(argv, '--log');
  if (project === undefined || logPath === undefined) {
    process.stderr.write('usage: --project <dir> --log <file>\n');
    return 2;
  }
  const budget = Number(arg(argv, '--budget-ms') ?? '20000');
  const result = await drill(project, budget, arg(argv, '--sarif'), logPath);
  if (result.stdout !== '') {process.stdout.write(result.stdout);}
  if (result.stderr !== '') {process.stderr.write(result.stderr);}
  return result.code;
}
