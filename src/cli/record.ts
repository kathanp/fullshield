import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/** Staging-only local file. No network. */
export async function writeEvidenceFile(cwd: string, files: readonly string[]): Promise<string> {
  const dir = join(cwd, '.fullshield');
  await mkdir(dir, { recursive: true });
  const rel = '.fullshield/evidence.json';
  const body = `${JSON.stringify({ files: [...files] }, null, 2)}\n`;
  await writeFile(join(cwd, rel), body, 'utf8');
  return rel;
}
