import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import type { ProgramIO } from '../cli/program.js';
import { formatCliError } from '../cli/errors.js';
import { DEFAULT_CONFIG } from '../core/config.js';
import type { ScanResult } from '../core/engine.js';
import { summarize, type Finding } from '../core/finding.js';
import { packageVersion } from '../core/version.js';
import { renderConsoleReport } from '../reporters/console.js';
import { renderJsonReport } from '../reporters/json.js';
import { ingestEnabled } from './flag.js';
import { IngestError } from './error.js';
import { ingestLocalFiles } from './load.js';
import { renderIngestSarif } from './sarif-out.js';

export interface IngestCliOptions {
  json?: boolean;
  sarif?: string;
  experimentalIngest?: boolean;
}

export async function runIngestCommand(
  files: readonly string[],
  opts: IngestCliOptions,
  io: ProgramIO,
): Promise<void> {
  if (!ingestEnabled(opts.experimentalIngest === true)) {
    throw new IngestError('', 'ingest requires FULLSHIELD_EXPERIMENTAL_INGEST=1');
  }
  const loaded = await ingestLocalFiles(files);
  for (const error of loaded.errors) {io.err(formatCliError(error));}
  const report = toScanResult(loaded.findings);
  io.out(opts.json === true ? renderJsonReport(report) : renderConsoleReport(report));
  if (opts.sarif !== undefined) {await writeFile(resolve(opts.sarif), renderIngestSarif(loaded), 'utf8');}
  if (loaded.errors.length > 0) {process.exitCode = 2;}
}

function toScanResult(findings: Finding[]): ScanResult {
  return {
    findings,
    summary: summarize(findings),
    metadata: {
      version: packageVersion(),
      startedAt: new Date().toISOString(),
      durationMs: 0,
      cwd: process.cwd(),
      filesScanned: findings.length,
      modulesRequested: [],
      modulesRun: [],
    },
    config: DEFAULT_CONFIG,
  };
}
