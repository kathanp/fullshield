import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface GhResult {
  status: number;
  stdout: string;
  stderr: string;
}

export type GhRunner = (args: string[]) => Promise<GhResult>;

export interface InitOptions {
  cwd: string;
  force?: boolean;
  /** Phase 553. Write profile: recommended and the Action-based workflow. */
  recommended?: boolean;
  /** Phase 556. CI-oriented defaults (Action workflow). */
  ci?: boolean;
  /** Phase 556. Never invoke `gh` to open a PR. */
  noPr?: boolean;
  /** Phase 556. Write a local first-scan Markdown summary file. */
  writeSummary?: boolean;
  /** Injectable `gh` for tests. Production leaves this unset (prints a manual recipe). */
  runGh?: GhRunner;
}

export interface InitResult {
  written: string[];
  prUrl?: string;
  summaryPath?: string;
  /** Printed when --ci would open a PR but no runGh was provided. */
  prHint?: string;
}

async function packageRoot(): Promise<string> {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 8; i += 1) {
    try {
      const raw = JSON.parse(await readFile(join(dir, 'package.json'), 'utf8')) as { name?: string };
      if (raw.name === 'fullshield') {return dir;}
    } catch {
      // keep walking up
    }
    dir = join(dir, '..');
  }
  return process.cwd();
}

async function writeIfMissing(path: string, contents: string, force: boolean): Promise<boolean> {
  if (!force) {
    try {
      await readFile(path);
      return false;
    } catch {
      // missing
    }
  }
  await mkdir(dirname(path), { recursive: true });
  const mode = path.endsWith('.sh') ? 0o755 : 0o644;
  await writeFile(path, contents, { mode });
  return true;
}

async function maybeOpenPr(
  cwd: string,
  written: string[],
  runGh: GhRunner,
): Promise<string | undefined> {
  if (written.length === 0) {return undefined;}
  if (!existsSync(join(cwd, '.git'))) {return undefined;}
  const branch = `fullshield/init-ci-${Date.now()}`;
  const steps: string[][] = [
    ['auth', 'status'],
    ['repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner'],
  ];
  for (const step of steps) {
    const check = await runGh(step);
    if (check.status !== 0) {return undefined;}
  }
  // Create branch/PR only via injected gh; never post review comments or request changes.
  const create = await runGh([
    'pr',
    'create',
    '--title',
    'chore: add FullShield CI',
    '--body',
    'Adds FullShield scan workflow and config. FullShield does not post pull-request comments.',
    '--head',
    branch,
  ]);
  if (create.status !== 0) {return undefined;}
  const url = create.stdout.trim().split('\n').find((line) => line.startsWith('http'));
  return url;
}

async function writeLocalSummary(cwd: string): Promise<string | undefined> {
  const name = 'fullshield-pr-summary.md';
  const body = [
    '# FullShield first scan',
    '',
    'Run `npx fullshield scan --pr-summary` after installing dependencies for a live summary.',
    'FullShield does not post pull-request comments.',
    '',
  ].join('\n');
  await writeFile(join(cwd, name), body, 'utf8');
  return name;
}

export async function runInit(options: InitOptions): Promise<InitResult> {
  const root = await packageRoot();
  const templates = join(root, 'templates');
  const recommended = options.recommended === true;
  const ci = options.ci === true;
  const useAction = recommended || ci;
  const configSrc = recommended
    ? join(templates, 'fullshield.config.recommended.json')
    : join(templates, 'fullshield.config.json');
  const workflowSrc = useAction
    ? join(templates, 'github-workflow-action.yml')
    : join(templates, 'github-workflow.yml');
  const files: Array<[string, string]> = [
    ['fullshield.config.json', configSrc],
    ['.github/workflows/fullshield.yml', workflowSrc],
    ['.github/workflows/fullshield-watch.yml', join(templates, 'github-watch.yml')],
    ['.gitlab-ci.yml', join(templates, 'gitlab-ci.yml')],
    ['.fullshield/pre-commit.sh', join(templates, 'pre-commit.sh')],
  ];
  if (recommended || ci) {
    files.push(['fullshield.policy.json', join(templates, 'policy', 'fullshield.policy.json')]);
  }
  if (recommended) {
    files.push(['.github/workflows/fullshield-diff.yml', join(templates, 'github-workflow-diff.yml')]);
  }
  const written: string[] = [];
  for (const [rel, src] of files) {
    const contents = await readFile(src, 'utf8');
    if (await writeIfMissing(join(options.cwd, rel), contents, options.force === true)) {
      written.push(rel);
    }
  }
  let summaryPath: string | undefined;
  if (options.writeSummary === true || ci) {
    summaryPath = await writeLocalSummary(options.cwd);
  }
  let prUrl: string | undefined;
  let prHint: string | undefined;
  if (ci && options.noPr !== true) {
    if (options.runGh !== undefined) {
      prUrl = await maybeOpenPr(options.cwd, written, options.runGh);
    } else {
      prHint =
        'To open a PR with these files: gh pr create --title "chore: add FullShield CI" --body "Adds FullShield CI. FullShield does not post pull-request comments."';
    }
  }
  return { written, prUrl, summaryPath, prHint };
}
