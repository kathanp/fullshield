import { readFile } from 'node:fs/promises';
import { basename, join } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import type { Finding } from '../../core/finding.js';
import { runConfigAstChecks } from './astChecks.js';
import { electronEnabled } from '../sast/experimental.js';
import { lockUsesElectron, packageUsesElectron, scanElectronSource } from './electron.js';
import { scanDockerfile } from './dockerfile.js';
import { scanPackageScripts } from './packageJson.js';

export const configModule: ScanModule = {
  name: 'config',
  async run(ctx) {
    const findings: Finding[] = [];
    const electronOn = electronEnabled();
    let usesElectron = false;
    const sources: Array<{ rel: string; text: string }> = [];
    for (const rel of ctx.files) {
      const base = basename(rel);
      if (base === 'Dockerfile' || base.endsWith('.dockerfile')) {
        try {
          findings.push(...scanDockerfile(rel, await readFile(join(ctx.cwd, rel), 'utf8')));
        } catch {
          continue;
        }
        continue;
      }
      if (base === 'package.json' || base === 'package-lock.json') {
        try {
          const text = await readFile(join(ctx.cwd, rel), 'utf8');
          if (base === 'package.json' && packageUsesElectron(text)) {usesElectron = true;}
          if (base === 'package-lock.json' && lockUsesElectron(text)) {usesElectron = true;}
          findings.push(...scanPackageScripts(rel, text));
        } catch {
          continue;
        }
      }
      if ((base === 'yarn.lock' || base === 'pnpm-lock.yaml') && !usesElectron) {
        try {
          const text = await readFile(join(ctx.cwd, rel), 'utf8');
          if (lockUsesElectron(text)) {usesElectron = true;}
        } catch {
          continue;
        }
      }
      if (!/\.[cm]?[jt]sx?$/.test(rel)) {continue;}
      try {
        const text = await readFile(join(ctx.cwd, rel), 'utf8');
        sources.push({ rel, text });
        findings.push(...(await runConfigAstChecks(rel, text)));
      } catch {
        continue;
      }
    }
    if (electronOn && usesElectron) {
      for (const source of sources) {findings.push(...scanElectronSource(source.rel, source.text));}
    }
    return findings;
  },
};
