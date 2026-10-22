import { scan } from '../core/engine.js';

interface AdvisoryItem {
  id: string;
  file: string;
  line: number;
  class: string;
}

interface AdvisoryFile {
  outOfScope?: string[];
  items: AdvisoryItem[];
}

function arg(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

export async function mine(dir: string, list: AdvisoryFile): Promise<string> {
  const result = await scan({ cwd: dir, modules: ['sast'], offline: true });
  const outOfScopeClasses = new Set(list.outOfScope ?? []);
  const misses: AdvisoryItem[] = [];
  const outOfScope: AdvisoryItem[] = [];
  for (const item of list.items) {
    if (outOfScopeClasses.has(item.class)) {
      outOfScope.push(item);
      continue;
    }
    const hit = result.findings.some((finding) => {
      const line = finding.line ?? 0;
      const sameClass = finding.ruleId === item.class || finding.cwe === item.class;
      const file = finding.file ?? '';
      const sameFile = file === item.file || file.endsWith(`/${item.file}`) || file.endsWith(`\\${item.file}`);
      return sameClass && sameFile && Math.abs(line - item.line) <= 3;
    });
    if (!hit) misses.push(item);
  }
  return JSON.stringify({ unreviewed: true, misses, outOfScope });
}

export async function main(argv: readonly string[]): Promise<number> {
  const dir = arg(argv, '--dir');
  const listPath = arg(argv, '--list');
  if (dir === undefined || listPath === undefined) {
    process.stderr.write('usage: --dir <tree> --list <json>\n');
    return 2;
  }
  const { readFileSync } = await import('node:fs');
  const list = JSON.parse(readFileSync(listPath, 'utf8')) as AdvisoryFile;
  process.stdout.write(`${await mine(dir, list)}\n`);
  return 0;
}
