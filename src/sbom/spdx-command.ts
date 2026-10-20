import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { buildSbom } from './index.js';
import { validateCycloneDx15 } from './cyclonedx.js';
import { buildSpdxSbom } from './spdx.js';
import { SpdxInputError } from './spdx-time.js';

interface SpdxCliOptions {
  out?: string;
  sbomTimestamp?: string;
  cyclonedxOut?: string;
}

interface SpdxCliIo {
  out(text: string): void;
}

export async function runSpdxCli(cwd: string, opts: SpdxCliOptions, io: SpdxCliIo): Promise<void> {
  if (opts.cyclonedxOut !== undefined) {await writeCycloneDx(cwd, opts.cyclonedxOut);}
  const spdx = await buildSpdxSbom(cwd, {
    created: opts.sbomTimestamp,
    cyclonedxFile: opts.cyclonedxOut,
  });
  const json = `${JSON.stringify(spdx, null, 2)}\n`;
  if (opts.out !== undefined) {
    await writeFile(resolve(opts.out), json, 'utf8');
    io.out(`Wrote SPDX 2.3 SBOM to ${opts.out}`);
    return;
  }
  io.out(json.trimEnd());
}

async function writeCycloneDx(cwd: string, file: string): Promise<void> {
  const doc = await buildSbom(cwd, {
    includeReach: process.env.FULLSHIELD_EXPERIMENTAL_SBOM_REACH === '1',
  });
  const errors = validateCycloneDx15(doc);
  if (errors.length > 0) {throw new SpdxInputError(`invalid SBOM: ${errors.join('; ')}`);}
  await writeFile(resolve(file), JSON.stringify(doc, null, 2), 'utf8');
}
