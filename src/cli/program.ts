import { resolve } from 'node:path';

import { Command } from 'commander';

import { scan } from '../core/engine.js';
import {
  MODULE_NAMES,
  SEVERITIES,
  isModuleName,
  isSeverity,
  meetsThreshold,
  type ModuleName,
  type Severity,
} from '../core/finding.js';
import { packageVersion } from '../core/version.js';
import { renderConsoleReport } from '../reporters/console.js';
import { renderJsonReport } from '../reporters/json.js';

export interface ProgramIO {
  out(text: string): void;
  err(text: string): void;
}

const defaultIO: ProgramIO = {
  out: (text) => process.stdout.write(`${text}\n`),
  err: (text) => process.stderr.write(`${text}\n`),
};

interface ScanCliOptions {
  json?: boolean;
  failOn?: string;
  modules?: string;
  config?: string;
}

function parseModules(value: string): ModuleName[] {
  const parts = value
    .split(',')
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  return parts.map((part) => {
    if (!isModuleName(part)) {
      throw new Error(`unknown module "${part}" (valid: ${MODULE_NAMES.join(', ')})`);
    }
    return part;
  });
}

function parseFailOn(value: string): Severity {
  if (!isSeverity(value)) {
    throw new Error(`invalid --fail-on severity "${value}" (valid: ${SEVERITIES.join(', ')})`);
  }
  return value;
}

export function createProgram(io: ProgramIO = defaultIO): Command {
  const program = new Command();
  program
    .name('fullshield')
    .description('Full-cycle security scanner for Node.js/TypeScript backends')
    .version(packageVersion());

  program
    .command('scan')
    .description('Scan a project directory for security findings')
    .argument('[path]', 'directory to scan', '.')
    .option('--json', 'machine-readable JSON output')
    .option('--fail-on <severity>', 'exit 1 if any finding is at or above this severity')
    .option('--modules <modules>', 'comma-separated subset of modules to run')
    .option('--config <path>', 'path to fullshield.config.json')
    .action(async (path: string, opts: ScanCliOptions) => {
      try {
        const failOnOverride = opts.failOn !== undefined ? parseFailOn(opts.failOn) : undefined;
        const modules = opts.modules !== undefined ? parseModules(opts.modules) : undefined;

        const result = await scan({
          cwd: resolve(path),
          modules,
          configPath: opts.config,
        });

        io.out(opts.json === true ? renderJsonReport(result) : renderConsoleReport(result));

        const failOn = failOnOverride ?? result.config.failOn;
        if (result.findings.some((f) => meetsThreshold(f.severity, failOn))) {
          process.exitCode = 1;
        }
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  return program;
}
