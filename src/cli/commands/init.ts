import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface InitOptions {
  cwd: string;
  force?: boolean;
  /** Phase 553. Write profile: recommended and the Action-based workflow. */
  recommended?: boolean;
}

export interface InitResult {
  written: string[];
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

export async function runInit(options: InitOptions): Promise<InitResult> {
  const root = await packageRoot();
  const templates = join(root, 'templates');
  const recommended = options.recommended === true;
  const configSrc = recommended
    ? join(templates, 'fullshield.config.recommended.json')
    : join(templates, 'fullshield.config.json');
  const workflowSrc = recommended
    ? join(templates, 'github-workflow-action.yml')
    : join(templates, 'github-workflow.yml');
  const files: Array<[string, string]> = [
    ['fullshield.config.json', configSrc],
    ['.github/workflows/fullshield.yml', workflowSrc],
    ['.github/workflows/fullshield-watch.yml', join(templates, 'github-watch.yml')],
    ['.gitlab-ci.yml', join(templates, 'gitlab-ci.yml')],
    ['.fullshield/pre-commit.sh', join(templates, 'pre-commit.sh')],
  ];
  const written: string[] = [];
  for (const [rel, src] of files) {
    const contents = await readFile(src, 'utf8');
    if (await writeIfMissing(join(options.cwd, rel), contents, options.force === true)) {
      written.push(rel);
    }
  }
  return { written };
}
