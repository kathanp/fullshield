#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const FLAG = 'FULLSHIELD_EXPERIMENTAL_FNMINE';
const entry = process.argv[1];
const direct = entry !== undefined && fileURLToPath(import.meta.url) === entry;
if (direct) {
  if (process.env[FLAG] !== '1') process.exit(0);
  if (process.env.FULLSHIELD_PHASE_INNER !== '1') {
    const dir = join(tmpdir(), 'fullshield-phase-ts');
    mkdirSync(dir, { recursive: true });
    const loader = join(dir, 'loader.mjs');
    const reg = join(dir, 'register.mjs');
    writeFileSync(loader, "export async function resolve(specifier, context, nextResolve) {\n  if ((specifier.startsWith('./') || specifier.startsWith('../')) && specifier.endsWith('.js')) {\n    try { return await nextResolve(specifier.slice(0, -3) + '.ts', context); }\n    catch { return nextResolve(specifier, context); }\n  }\n  return nextResolve(specifier, context);\n}\n");
    writeFileSync(reg, "import { register } from 'node:module';\nimport { pathToFileURL } from 'node:url';\nregister(pathToFileURL(" + JSON.stringify(loader) + ").href, { parentURL: import.meta.url });\n");
    const result = spawnSync(process.execPath, ['--experimental-transform-types', '--disable-warning=ExperimentalWarning', '--import', reg, fileURLToPath(import.meta.url), ...process.argv.slice(2)], {
      stdio: 'inherit',
      env: { ...process.env, FULLSHIELD_PHASE_INNER: '1' },
    });
    process.exit(result.status === null ? 1 : result.status);
  }
  const mod = await import('../src/phases/p474.ts');
  process.exit(await mod.main(process.argv.slice(2)));
}
