import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface InitOptions {
  cwd: string;
  force?: boolean;
}

export interface InitResult {
  written: string[];
}

async function packageRoot(): Promise<string> {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 8; i += 1) {
    try {
      const raw = JSON.parse(await readFile(join(dir, 'package.json'), 'utf8')) as { name?: string };
      if (raw.name === 'fullshield') return dir;
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
  const files: Array<[string, string]> = [
    ['fullshield.config.json', join(templates, 'fullshield.config.json')],
    ['.github/workflows/fullshield.yml', join(templates, 'github-workflow.yml')],
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
