import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { Command } from 'commander';

import { scan } from '../core/engine.js';
import { writeLastScan } from '../core/lastScan.js';
import { runFix } from '../fixer/index.js';
import { runInit } from './commands/init.js';
import { formatSummary, loadLastScan, notifyEmail, notifySlack, notifyWebhook } from '../notifiers/index.js';
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
import { renderHtmlReport } from '../reporters/html.js';
import { renderJsonReport } from '../reporters/json.js';
import { renderMarkdownReport } from '../reporters/markdown.js';
import { renderSarifReport } from '../reporters/sarif.js';

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
  staged?: boolean;
  offline?: boolean;
  config?: string;
  sarif?: string;
  markdown?: string;
  html?: string;
  updateBaseline?: boolean;
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
    .option('--staged', 'scan only files staged in git (pre-commit mode)')
    .option('--offline', 'use the OSV cache only (no network)')
    .option('--config <path>', 'path to fullshield.config.json')
    .option('--sarif <file>', 'write a SARIF 2.1.0 report to this path')
    .option('--markdown <file>', 'write a Markdown report to this path')
    .option('--html <file>', 'write an HTML report to this path')
    .option('--update-baseline', 'record current findings as accepted (CI fails only on new ones)')
    .action(async (path: string, opts: ScanCliOptions) => {
      try {
        const failOnOverride = opts.failOn !== undefined ? parseFailOn(opts.failOn) : undefined;
        const modules = opts.modules !== undefined ? parseModules(opts.modules) : undefined;

        const result = await scan({
          cwd: resolve(path),
          modules,
          configPath: opts.config,
          staged: opts.staged === true,
          offline: opts.offline === true,
          updateBaseline: opts.updateBaseline === true,
        });

        if (opts.sarif !== undefined) {
          await writeFile(resolve(opts.sarif), renderSarifReport(result), 'utf8');
        }
        if (opts.markdown !== undefined) {
          await writeFile(resolve(opts.markdown), renderMarkdownReport(result), 'utf8');
        }
        if (opts.html !== undefined) {
          await writeFile(resolve(opts.html), renderHtmlReport(result), 'utf8');
        }

        await writeLastScan(resolve(path), result);

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

  program
    .command('fix')
    .description('Propose or apply safe auto-fixes (dry-run by default)')
    .argument('[path]', 'directory to fix', '.')
    .option('--apply', 'write safe fixes (requires a clean git tree)')
    .option('--force', 'apply even if the tree is dirty or not a git repo')
    .option('--unsafe', 'include major-version bumps and code patches marked unsafe')
    .option('--no-branch', 'do not create a fullshield/fixes-* branch')
    .option('--modules <modules>', 'comma-separated subset of modules to scan')
    .action(async (path: string, opts: {
      apply?: boolean;
      force?: boolean;
      unsafe?: boolean;
      branch?: boolean;
      modules?: string;
    }) => {
      try {
        const modules = opts.modules !== undefined ? parseModules(opts.modules) : undefined;
        const result = await runFix({
          cwd: resolve(path),
          modules,
          apply: opts.apply === true,
          force: opts.force === true,
          unsafe: opts.unsafe === true,
          noBranch: opts.branch === false,
        });
        if (result.patches.length === 0) {
          io.out('No safe fixes available.');
        } else {
          for (const patch of result.patches) {
            io.out(`# ${patch.ruleId} ${patch.file}${patch.safe ? '' : ' (unsafe)'}`);
            io.out(patch.diff);
            io.out('');
          }
        }
        if (result.reverted) {
          io.err('fullshield: project tests failed; fixes were reverted');
          process.exitCode = 1;
        } else if (opts.apply === true && result.applied) {
          io.out(`Applied ${result.patches.length} fix(es)${result.branch !== undefined ? ` on ${result.branch}` : ''}.`);
        } else if (opts.apply !== true) {
          io.out('Dry run. Re-run with --apply to write safe fixes.');
        }
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('init')
    .description('Write fullshield.config.json, CI workflows, and a pre-commit hook')
    .argument('[path]', 'project directory', '.')
    .option('--force', 'overwrite existing generated files')
    .action(async (path: string, opts: { force?: boolean }) => {
      try {
        const result = await runInit({ cwd: resolve(path), force: opts.force === true });
        if (result.written.length === 0) {
          io.out('Nothing to write (files already exist). Pass --force to overwrite.');
        } else {
          io.out(`Wrote ${result.written.join(', ')}`);
        }
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('notify')
    .description('Send a summary of the last scan (Slack, webhook, or SMTP)')
    .argument('[path]', 'project directory that was scanned', '.')
    .option('--slack [url]', 'Slack incoming webhook (or $FULLSHIELD_SLACK_WEBHOOK)')
    .option('--webhook <url>', 'generic JSON webhook')
    .option('--email', 'SMTP using FULLSHIELD_SMTP_* env vars')
    .action(async (path: string, opts: { slack?: string | true; webhook?: string; email?: boolean }) => {
      try {
        const summary = await loadLastScan(resolve(path));
        if (opts.slack !== undefined) {
          const url = opts.slack === true ? process.env.FULLSHIELD_SLACK_WEBHOOK : opts.slack;
          if (url === undefined || url.length === 0) {
            throw new Error('Slack webhook URL missing (pass --slack URL or set FULLSHIELD_SLACK_WEBHOOK)');
          }
          await notifySlack(url, summary);
        }
        if (opts.webhook !== undefined) {
          await notifyWebhook(opts.webhook, summary);
        }
        if (opts.email === true) {
          const host = process.env.FULLSHIELD_SMTP_HOST;
          const port = Number(process.env.FULLSHIELD_SMTP_PORT ?? '25');
          const from = process.env.FULLSHIELD_SMTP_FROM;
          const to = process.env.FULLSHIELD_NOTIFY_EMAIL;
          if (host === undefined || from === undefined || to === undefined) {
            throw new Error('email notify requires FULLSHIELD_SMTP_HOST, FULLSHIELD_SMTP_FROM, FULLSHIELD_NOTIFY_EMAIL');
          }
          await notifyEmail({ host, port, from, to, summary });
        }
        io.out(formatSummary(summary));
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  return program;
}
