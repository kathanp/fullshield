import { readFile } from 'node:fs/promises';
import { basename, join } from 'node:path';

import type { ScanModule } from '../../core/engine.js';
import type { Finding } from '../../core/finding.js';
import { runConfigAstChecks } from './astChecks.js';
import { scanDockerfile } from './dockerfile.js';
import { scanPackageScripts } from './packageJson.js';

export const configModule: ScanModule = {
  name: 'config',
  async run(ctx) {
    const findings: Finding[] = [];
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
          findings.push(...scanPackageScripts(rel, await readFile(join(ctx.cwd, rel), 'utf8')));
        } catch {
          continue;
        }
      }
      if (!/\.[cm]?[jt]sx?$/.test(rel)) {continue;}
      try {
        findings.push(...(await runConfigAstChecks(rel, await readFile(join(ctx.cwd, rel), 'utf8'))));
      } catch {
        continue;
      }
    }
    return findings;
  },
};
