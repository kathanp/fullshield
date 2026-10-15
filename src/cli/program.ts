import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { Command } from 'commander';

import { scan } from '../core/engine.js';
import { readLastScanIds, writeLastScan } from '../core/lastScan.js';
import { diffNewFindings } from '../core/watch.js';
import { runFix } from '../fixer/index.js';
import { runInit } from './commands/init.js';
import { formatSummary, loadLastScan, notifyEmail, notifySlack, notifyWebhook } from '../notifiers/index.js';
import {
  MODULE_NAMES,
  SEVERITIES,
  isModuleName,
  isSeverity,
  failsCi,
  meetsThreshold,
  summarize,
  type ModuleName,
  type Severity,
} from '../core/finding.js';
import { createAiClient, isLiveAi } from '../ai/provider.js';
import { runAiFix } from '../ai/fixLoop.js';
import { packageVersion } from '../core/version.js';
import { renderConsoleReport } from '../reporters/console.js';
import { renderHtmlReport } from '../reporters/html.js';
import { renderJsonReport } from '../reporters/json.js';
import { renderMarkdownReport } from '../reporters/markdown.js';
import { renderSarifReport } from '../reporters/sarif.js';
import { buildSbom } from '../sbom/index.js';
import { validateCycloneDx15 } from '../sbom/cyclonedx.js';
import { runEdge } from '../modules/edge/index.js';

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
  offlineSafe?: boolean;
  config?: string;
  sarif?: string;
  markdown?: string;
  html?: string;
  updateBaseline?: boolean;
  ai?: string | true;
  emitVirtualPatches?: boolean | string;
  changed?: boolean;
  since?: string;
  experimentalSastGaps?: boolean;
  experimentalFrameworks?: boolean;
  experimentalSecretsAdv?: boolean;
  history?: boolean;
  bundle?: string;
  verifySecrets?: boolean;
  iOwnTheseCredentials?: boolean;
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

function parseAiMode(value: string | true | undefined): 'explain' | undefined {
  if (value === undefined) return undefined;
  if (value === true || value === 'explain') return 'explain';
  if (value === 'triage' || value === 'logic') {
    throw new Error(
      `--ai ${value} is not shipped in 0.1.0 (experimental: --ai explain, fix --ai)`,
    );
  }
  throw new Error(`invalid --ai mode "${value}" (valid: explain)`);
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
    .option('--offline-safe', 'alias of --offline')
    .option('--config <path>', 'path to fullshield.config.json')
    .option('--sarif <file>', 'write a SARIF 2.1.0 report to this path')
    .option('--markdown <file>', 'write a Markdown report to this path')
    .option('--html <file>', 'write an HTML report to this path')
    .option('--update-baseline', 'record current findings as accepted (CI fails only on new ones)')
    .option('--ai [mode]', 'experimental: explain findings (off = zero AI network calls)')
    .option('--emit-virtual-patches [file]', 'experimental: write .fullshield/vpatches.json')
    .option('--changed', 'experimental: scan git staged/changed files only')
    .option('--since <ref>', 'experimental: scan files changed since a git ref')
    .option(
      '--experimental-sast-gaps',
      'experimental: ORM raw / sh -c / execa / zx sinks (FULLSHIELD_EXPERIMENTAL_SAST_GAPS=1)',
    )
    .option(
      '--experimental-frameworks',
      'experimental: Next.js / NestJS / Hono / Koa taint + AUTH (FULLSHIELD_EXPERIMENTAL_FRAMEWORKS=1)',
    )
    .option(
      '--experimental-secrets-adv',
      'experimental: history/bundle/verify-secrets (FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1)',
    )
    .option('--history', 'experimental: scan git history for secrets (requires FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1)')
    .option(
      '--bundle <dir>',
      'experimental: scan a built client bundle for browser-exposed keys (requires FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1)',
    )
    .option(
      '--verify-secrets',
      'experimental: check whether detected keys are live (never default; requires --i-own-these-credentials)',
    )
    .option(
      '--i-own-these-credentials',
      'required with --verify-secrets: you own these credentials; read-only identity checks only',
    )
    .action(async (path: string, opts: ScanCliOptions) => {
      try {
        const failOnOverride = opts.failOn !== undefined ? parseFailOn(opts.failOn) : undefined;
        const modules = opts.modules !== undefined ? parseModules(opts.modules) : undefined;
        const ai = parseAiMode(opts.ai);
        if (opts.experimentalSastGaps === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_SAST_GAPS = '1';
        }
        if (opts.experimentalFrameworks === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_FRAMEWORKS = '1';
        }
        if (opts.experimentalSecretsAdv === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_SECRETS_ADV = '1';
        }

        const result = await scan({
          cwd: resolve(path),
          modules,
          configPath: opts.config,
          staged: opts.staged === true,
          offline: opts.offline === true || opts.offlineSafe === true,
          updateBaseline: opts.updateBaseline === true,
          ai,
          changed: opts.changed === true,
          since: opts.since,
          experimentalIncremental: process.env.FULLSHIELD_EXPERIMENTAL_PLATFORM === '1',
          history: opts.history === true,
          bundle: opts.bundle !== undefined ? resolve(path, opts.bundle) : undefined,
          verifySecrets: opts.verifySecrets === true,
          iOwnTheseCredentials: opts.iOwnTheseCredentials === true,
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

        if (opts.emitVirtualPatches !== undefined) {
          if (process.env.FULLSHIELD_EXPERIMENTAL_VPATCH !== '1') {
            throw new Error('--emit-virtual-patches requires FULLSHIELD_EXPERIMENTAL_VPATCH=1');
          }
          const { emitVirtualPatches } = await import('../runtime/rasp/vpatchIo.js');
          const out =
            typeof opts.emitVirtualPatches === 'string'
              ? resolve(opts.emitVirtualPatches)
              : resolve(path, '.fullshield', 'vpatches.json');
          emitVirtualPatches(result.findings, out);
          io.err(`wrote virtual patches ${out}`);
        }

        io.out(opts.json === true ? renderJsonReport(result) : renderConsoleReport(result));

        const failOn = failOnOverride ?? result.config.failOn;
        if (result.findings.some((f) => failsCi(f, failOn))) {
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
    .option('--ai', 'draft a verified patch for findings without a rule-based fix (reviewable diff only)')
    .action(async (path: string, opts: {
      apply?: boolean;
      force?: boolean;
      unsafe?: boolean;
      branch?: boolean;
      modules?: string;
      ai?: boolean;
    }) => {
      try {
        const modules = opts.modules !== undefined ? parseModules(opts.modules) : undefined;
        if (opts.ai === true) {
          const client = createAiClient({ enabled: true, useFixtures: !isLiveAi() });
          const aiFix = await runAiFix({ cwd: resolve(path), client });
          if (!aiFix.accepted) {
            io.out('No verified AI patch (finding remained, new findings appeared, or tests failed).');
            return;
          }
          io.out(`# AI patch ${aiFix.file ?? ''} (reviewable diff; not applied)`);
          io.out(aiFix.diff);
          return;
        }
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

  program
    .command('sbom')
    .description('Write a CycloneDX 1.5 SBOM for the project')
    .argument('[path]', 'project directory', '.')
    .option('--format <format>', 'sbom format', 'cyclonedx')
    .option('--out <file>', 'write to this file instead of stdout')
    .action(async (path: string, opts: { format?: string; out?: string }) => {
      try {
        if (opts.format !== undefined && opts.format !== 'cyclonedx') {
          throw new Error(`unsupported SBOM format "${opts.format}" (valid: cyclonedx)`);
        }
        const doc = await buildSbom(resolve(path));
        const errors = validateCycloneDx15(doc);
        if (errors.length > 0) throw new Error(`invalid SBOM: ${errors.join('; ')}`);
        const json = JSON.stringify(doc, null, 2);
        if (opts.out !== undefined) {
          await writeFile(resolve(opts.out), json, 'utf8');
          io.out(`Wrote CycloneDX 1.5 SBOM to ${opts.out}`);
        } else {
          io.out(json);
        }
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('edge')
    .description('Check CDN/WAF, TLS, headers, and common exposure paths on a URL you own')
    .argument('<url>', 'https URL to probe (GET/HEAD only; no crawl)')
    .option('--json', 'machine-readable JSON output')
    .action(async (url: string, opts: { json?: boolean }) => {
      try {
        if (!/^https?:\/\//i.test(url)) throw new Error('edge requires an explicit http(s) URL');
        const delayRaw = process.env.FULLSHIELD_EDGE_DELAY;
        const delayMs = delayRaw !== undefined && delayRaw.length > 0 ? Number(delayRaw) : 1000;
        const findings = await runEdge({ url, delayMs });
        const payload = { findings, summary: summarize(findings), url };
        if (opts.json === true) {
          io.out(JSON.stringify(payload, null, 2));
        } else {
          io.out(`FullShield edge ${url} — ${payload.summary.total} finding(s)`);
          for (const f of findings) io.out(`  [${f.ruleId}] ${f.message}`);
        }
        if (findings.some((f) => meetsThreshold(f.severity, 'high'))) process.exitCode = 1;
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('watch')
    .description('Rescan dependencies and alert only on NEW vulnerabilities')
    .argument('[path]', 'project directory', '.')
    .option('--offline', 'use the OSV cache only (no network)')
    .option('--webhook <url>', 'POST only when there are new findings')
    .option('--fail-on <severity>', 'exit 1 if a new finding is at or above this severity')
    .action(async (path: string, opts: { offline?: boolean; webhook?: string; failOn?: string }) => {
      try {
        const cwd = resolve(path);
        const failOn = opts.failOn !== undefined ? parseFailOn(opts.failOn) : undefined;
        const previous = await readLastScanIds(cwd);
        const result = await scan({
          cwd,
          modules: ['deps'],
          offline: opts.offline === true,
        });
        const fresh = diffNewFindings(
          result.findings.filter((f) => f.ruleId === 'DEPS-VULN-001'),
          previous,
        );
        await writeLastScan(cwd, result);
        if (fresh.length === 0) {
          io.out('No new vulnerabilities.');
          return;
        }
        io.out(`${fresh.length} new vulnerabilit${fresh.length === 1 ? 'y' : 'ies'}.`);
        if (opts.webhook !== undefined) {
          await notifyWebhook(opts.webhook, {
            total: fresh.length,
            bySeverity: result.summary.bySeverity,
            version: result.metadata.version,
            cwd,
          });
        }
        const gate = failOn ?? result.config.failOn;
        if (fresh.some((f) => meetsThreshold(f.severity, gate))) process.exitCode = 1;
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('threat-model')
    .description('Experimental STRIDE + Mermaid threat model (FULLSHIELD_EXPERIMENTAL_PLATFORM=1)')
    .argument('[path]', 'project directory', '.')
    .action(async (path: string) => {
      try {
        if (process.env.FULLSHIELD_EXPERIMENTAL_PLATFORM !== '1') {
          throw new Error('threat-model requires FULLSHIELD_EXPERIMENTAL_PLATFORM=1');
        }
        const { buildThreatModel } = await import('../threat/index.js');
        const model = buildThreatModel(resolve(path), { experimental: true });
        io.out(JSON.stringify({ routes: model.routes.length, stride: model.stride, mermaid: model.mermaid }));
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('report')
    .description('Reports (experimental --serve dashboard; --compliance mapping)')
    .option('--serve', 'local dashboard (FULLSHIELD_EXPERIMENTAL_PLATFORM=1)')
    .option('--compliance <standard>', 'evidence-style mapping (pci). Not a certification or audit.')
    .argument('[path]', 'project directory', '.')
    .action(async (path: string, opts: { serve?: boolean; compliance?: string }) => {
      try {
        if (opts.compliance !== undefined) {
          if (process.env.FULLSHIELD_EXPERIMENTAL_COMPLIANCE !== '1') {
            throw new Error('report --compliance requires FULLSHIELD_EXPERIMENTAL_COMPLIANCE=1');
          }
          const result = await scan({ cwd: resolve(path), offline: true });
          const { scanIac } = await import('../iac/index.js');
          const iac = scanIac(resolve(path), {
            experimental: process.env.FULLSHIELD_EXPERIMENTAL_IAC === '1',
          });
          const { renderCompliance } = await import('../compliance/index.js');
          io.out(renderCompliance([...result.findings, ...iac], opts.compliance));
          return;
        }
        if (opts.serve !== true) {
          io.out('pass --serve or --compliance <standard>');
          return;
        }
        if (process.env.FULLSHIELD_EXPERIMENTAL_PLATFORM !== '1') {
          throw new Error('report --serve requires FULLSHIELD_EXPERIMENTAL_PLATFORM=1');
        }
        const { startDashboard } = await import('../dashboard/index.js');
        const started = await startDashboard({ dir: resolve(path), experimental: true });
        io.out(`dashboard listening on http://127.0.0.1:${started.port} (Host must be localhost or 127.0.0.1)`);
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('iac')
    .description('Experimental IaC scan (FULLSHIELD_EXPERIMENTAL_IAC=1)')
    .argument('[path]', 'project directory', '.')
    .action(async (path: string) => {
      try {
        if (process.env.FULLSHIELD_EXPERIMENTAL_IAC !== '1') {
          throw new Error('iac requires FULLSHIELD_EXPERIMENTAL_IAC=1');
        }
        const { scanIac } = await import('../iac/index.js');
        const findings = scanIac(resolve(path), { experimental: true });
        io.out(JSON.stringify({ findings }));
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('mcp')
    .description('Experimental MCP server (read-only; requires FULLSHIELD_EXPERIMENTAL_MCP=1)')
    .option('--list-tools', 'print tool names and exit')
    .option('--stdio', 'official MCP SDK stdio transport (initialize handshake)')
    .action(async (opts: { listTools?: boolean; stdio?: boolean }) => {
      try {
        if (process.env.FULLSHIELD_EXPERIMENTAL_MCP !== '1') {
          throw new Error('mcp requires FULLSHIELD_EXPERIMENTAL_MCP=1');
        }
        const { createMcpSession, handleMcpRequest, listMcpTools, startMcpStdio } = await import('../mcp/index.js');
        if (opts.listTools) {
          io.out(listMcpTools().map((t) => t.name).join('\n'));
          return;
        }
        if (opts.stdio) {
          await startMcpStdio({ experimental: true });
          return;
        }
        const session = createMcpSession({ experimental: true });
        const chunks: Buffer[] = [];
        for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
        const text = Buffer.concat(chunks).toString('utf8').trim();
        if (!text) {
          io.out(JSON.stringify({ tools: listMcpTools() }));
          return;
        }
        const req = JSON.parse(text) as { jsonrpc?: string; id?: number; method?: string };
        io.out(JSON.stringify(await handleMcpRequest(session, req)));
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('confirm')
    .description('Experimental exploit confirm (localhost/127.0.0.1/FullShield container only)')
    .argument('<url>', 'target base URL')
    .action(async (url: string) => {
      try {
        if (process.env.FULLSHIELD_EXPERIMENTAL_CONFIRM !== '1') {
          throw new Error('confirm requires FULLSHIELD_EXPERIMENTAL_CONFIRM=1');
        }
        const { assertLocalTarget, confirmTarget } = await import('../confirm/index.js');
        assertLocalTarget(url);
        const result = await confirmTarget(url, { experimental: true, routes: [] });
        io.out(JSON.stringify({ ok: true, confirmations: result.confirmations }));
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('install')
    .description('Experimental install-guard (requires FULLSHIELD_EXPERIMENTAL_SUPPLY=1)')
    .argument('<pkg>', 'package spec (never executed; analyzed statically)')
    .option('--dir <path>', 'local extracted package directory (tests / offline)')
    .action(async (pkg: string, opts: { dir?: string }) => {
      try {
        if (process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY !== '1') {
          throw new Error('install requires FULLSHIELD_EXPERIMENTAL_SUPPLY=1');
        }
        const { installGuard } = await import('../supply/index.js');
        const result = await installGuard(pkg, {
          experimental: true,
          extractDir: opts.dir ? resolve(opts.dir) : undefined,
        });
        if (result.findings.length > 0) {
          for (const f of result.findings) {
            io.out(`${f.ruleId} ${f.severity} ${f.message}`);
          }
          process.exitCode = 1;
          return;
        }
        io.out(`static checks passed for ${pkg}; next step would be npm install --ignore-scripts`);
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('agent')
    .description('Experimental remediation agent (FULLSHIELD_EXPERIMENTAL_AGENT=1). Mock/localhost API + local git only.')
    .argument('[path]', 'project directory', '.')
    .option('--max-prs <n>', 'maximum pull requests to open', '3')
    .action(async (path: string, opts: { maxPrs?: string }) => {
      try {
        if (process.env.FULLSHIELD_EXPERIMENTAL_AGENT !== '1') {
          throw new Error('agent requires FULLSHIELD_EXPERIMENTAL_AGENT=1');
        }
        const { runAgent } = await import('../agent/index.js');
        const result = await runAgent({
          cwd: resolve(path),
          experimental: true,
          maxPrs: Number(opts.maxPrs ?? 3),
          apiBase: process.env.FULLSHIELD_AGENT_API,
          repo: process.env.FULLSHIELD_AGENT_REPO,
          token: process.env.FULLSHIELD_AGENT_TOKEN,
        });
        io.out(JSON.stringify({ prs: result.prs, stoppedOnTestFailure: result.stoppedOnTestFailure, merged: result.merged }));
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  program
    .command('honey')
    .description('Experimental honeytokens (requires FULLSHIELD_EXPERIMENTAL_HONEY=1)')
    .command('init')
    .argument('[path]', 'project directory', '.')
    .action(async (path: string) => {
      try {
        if (process.env.FULLSHIELD_EXPERIMENTAL_HONEY !== '1') {
          throw new Error('honey init requires FULLSHIELD_EXPERIMENTAL_HONEY=1');
        }
        const { honeyInit } = await import('../runtime/rasp/honeyInit.js');
        const canaries = honeyInit(resolve(path));
        io.out(`wrote honeytokens (.env.backup). decoys: /admin.php /.git/config /wp-login.php`);
        io.out(`canary prefix ${canaries.awsKey.slice(0, 4)}****`);
      } catch (error) {
        io.err(`fullshield: ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 2;
      }
    });

  return program;
}
