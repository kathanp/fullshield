import { readFile } from 'node:fs/promises';

import { compileSemgrepDocument, type CompiledSemgrepRule } from './compile.js';

const INSTALL_YAML = 'install yaml to use user-supplied semgrep rules';

async function parseYaml(text: string): Promise<unknown> {
  let parse: (input: string) => unknown;
  try {
    const imported = await import('yaml');
    parse = imported.parse;
  } catch {
    throw new Error(INSTALL_YAML);
  }
  return parse(text);
}

/**
 * Load and compile a user rules file.
 * `enabled` false returns before the file is read or parsed.
 */
export async function loadUserSemgrepRules(file: string, enabled: boolean): Promise<CompiledSemgrepRule[]> {
  if (!enabled) return [];
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? 'error';
    throw new Error(`cannot read semgrep rules ${file}: ${code}`);
  }
  let doc: unknown;
  try {
    doc = await parseYaml(text);
  } catch (error) {
    if (error instanceof Error && error.message === INSTALL_YAML) throw error;
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`cannot read semgrep rules ${file}: ${message}`);
  }
  return compileSemgrepDocument(doc);
}
