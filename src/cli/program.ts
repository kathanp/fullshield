import { readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

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
import { PRIORITY_FLAG } from '../priority/score.js';
import { packageVersion } from '../core/version.js';
import { renderGithubAnnotations, renderGitlabCodeQuality, renderJunitReport } from '../reporters/ci.js';
import { renderConsoleReport } from '../reporters/console.js';
import { renderHtmlReport } from '../reporters/html.js';
import { renderJsonReport } from '../reporters/json.js';
import { renderMarkdownReport } from '../reporters/markdown.js';
import { renderSarifReport } from '../reporters/sarif.js';
import { addedFails, diffScans, parseScanDocument, renderDiffText } from '../diff/index.js';
import { CI_REPORTS_FLAG, DIFF_FLAG, diffEnabled } from '../modules/sast/experimental.js';
import { POLICY_FLAG, renderPrSummary } from '../policy/index.js';
import { diffLockedPackages, lockAtRef, packagesFromLock, releaseAgeLabel } from '../deps-diff/index.js';
import { registryCachePath, releaseFactsFromCache } from '../provenance/index.js';
import { explainFinding } from '../explain/index.js';
import { queryOsv } from '../modules/deps/osv.js';
import { osvSeverity } from '../modules/deps/semver.js';
import { buildSbom } from '../sbom/index.js';
import { validateCycloneDx15 } from '../sbom/cyclonedx.js';
import { runEdge } from '../modules/edge/index.js';
import { runHostCheck } from '../host/index.js';
import { runDoctor } from './commands/doctor.js';
import { formatCliError } from './errors.js';

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
  all?: boolean;
  failOn?: string;
  modules?: string;
  staged?: boolean;
  offline?: boolean;
  offlineSafe?: boolean;
  config?: string;
  sarif?: string;
  markdown?: string;
  html?: string;
  githubAnnotations?: string;
  junit?: string;
  gitlab?: string;
  experimentalCiReports?: boolean;
  updateBaseline?: boolean;
  ai?: string | true;
  emitVirtualPatches?: boolean | string;
  changed?: boolean;
  since?: string;
  experimentalSastGaps?: boolean;
  experimentalFrameworks?: boolean;
  experimentalClasses?: boolean;
  experimentalSecretsAdv?: boolean;
  history?: boolean;
  bundle?: string;
  verifySecrets?: boolean;
  iOwnTheseCredentials?: boolean;
  experimentalVex?: boolean;
  experimentalReachEvidence?: boolean;
  experimentalLockfiles?: boolean;
  experimentalSupply?: boolean;
  experimentalWorkspaces?: boolean;
  experimentalSarifV2?: boolean;
  experimentalCustomSanitizers?: boolean;
  experimentalValidation?: boolean;
  taintSummaries?: boolean;
  experimentalMcpcfg?: boolean;
  includeHome?: boolean;
  prSummary?: boolean;
  experimentalPriority?: boolean;
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
    .version(packageVersion())
    .option('--debug', 'print stack traces on CLI errors');

  program
    .command('scan')
    .description('Scan a project directory for security findings')
    .argument('[path]', 'directory to scan', '.')
    .option('--json', 'machine-readable JSON output')
    .option('--all', 'print every finding in the console, with no 20-row cap')
    .option('--fail-on <severity>', 'exit 1 if any finding is at or above this severity')
    .option('--modules <modules>', 'comma-separated subset of modules to run')
    .option('--staged', 'scan only files staged in git (pre-commit mode)')
    .option('--offline', 'use the OSV cache only (no network)')
    .option('--offline-safe', 'alias of --offline')
    .option('--config <path>', 'path to fullshield.config.json')
    .option('--sarif <file>', 'write a SARIF 2.1.0 report to this path')
    .option('--markdown <file>', 'write a Markdown report to this path')
    .option('--html <file>', 'write an HTML report to this path')
    .option(
      '--experimental-ci-reports',
      'experimental: GitHub annotations, JUnit, and GitLab Code Quality (FULLSHIELD_EXPERIMENTAL_CI_REPORTS=1)',
    )
    .option(
      '--github-annotations <file>',
      'experimental: GitHub Actions workflow commands (requires FULLSHIELD_EXPERIMENTAL_CI_REPORTS=1)',
    )
    .option('--junit <file>', 'experimental: JUnit XML (requires FULLSHIELD_EXPERIMENTAL_CI_REPORTS=1)')
    .option(
      '--gitlab <file>',
      'experimental: GitLab Code Quality JSON (requires FULLSHIELD_EXPERIMENTAL_CI_REPORTS=1)',
    )
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
      '--experimental-classes',
      'experimental: ReDoS/deser/XXE/upload/cookie/CSRF/mass-assign/timing/hash/GQL/trust-proxy (FULLSHIELD_EXPERIMENTAL_CLASSES=1)',
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
    .option(
      '--experimental-vex',
      'experimental: worm/workflow indicators, overrides, provenance, VEX (FULLSHIELD_EXPERIMENTAL_VEX=1)',
    )
    .option(
      '--experimental-reach-evidence',
      'experimental: record why a dependency reachability class was chosen (FULLSHIELD_EXPERIMENTAL_REACH_EVIDENCE=1)',
    )
    .option(
      '--experimental-lockfiles',
      'experimental: yarn berry, pnpm v9, and bun.lock (FULLSHIELD_EXPERIMENTAL_LOCKFILES=1)',
    )
    .option(
      '--experimental-supply',
      'experimental: supply-chain campaign heuristics (FULLSHIELD_EXPERIMENTAL_SUPPLY=1)',
    )
    .option(
      '--experimental-workspaces',
      'experimental: scan each workspace lockfile (FULLSHIELD_EXPERIMENTAL_WORKSPACES=1)',
    )
    .option(
      '--experimental-sarif-v2',
      'experimental: extra SARIF fields (FULLSHIELD_EXPERIMENTAL_SARIF_V2=1)',
    )
    .option(
      '--experimental-custom-sanitizers',
      'experimental: config-declared sources and sanitizers (FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS=1)',
    )
    .option(
      '--experimental-validation',
      'experimental: route schema validation inference (FULLSHIELD_EXPERIMENTAL_VALIDATION=1)',
    )
    .option('--taint-summaries', 'cache per-function taint summaries (FULLSHIELD_TAINT_SUMMARIES=1)')
    .option(
      '--experimental-mcpcfg',
      'experimental: MCP client/server config rules (FULLSHIELD_EXPERIMENTAL_MCPCFG=1)',
    )
    .option(
      '--experimental-priority',
      `experimental: deterministic priority score (${PRIORITY_FLAG}=1)`,
    )
    .option(
      '--include-home',
      'experimental: also scan MCP configs in the home directory (requires FULLSHIELD_EXPERIMENTAL_MCPCFG=1)',
    )
    .option(
      '--pr-summary',
      'experimental: deterministic Markdown of new findings versus baseline (FULLSHIELD_EXPERIMENTAL_POLICY=1)',
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
        if (opts.experimentalClasses === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_CLASSES = '1';
        }
        if (opts.experimentalSecretsAdv === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_SECRETS_ADV = '1';
        }
        if (opts.experimentalVex === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_VEX = '1';
        }
        if (opts.experimentalReachEvidence === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_REACH_EVIDENCE = '1';
        }
        if (opts.experimentalLockfiles === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_LOCKFILES = '1';
        }
        if (opts.experimentalSupply === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_SUPPLY = '1';
        }
        if (opts.experimentalWorkspaces === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_WORKSPACES = '1';
        }
        if (opts.experimentalSarifV2 === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_SARIF_V2 = '1';
        }
        if (opts.experimentalCustomSanitizers === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS = '1';
        }
        if (opts.experimentalValidation === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_VALIDATION = '1';
        }
        if (opts.taintSummaries === true) {
          process.env.FULLSHIELD_TAINT_SUMMARIES = '1';
        }
        if (opts.experimentalMcpcfg === true) {
          process.env.FULLSHIELD_EXPERIMENTAL_MCPCFG = '1';
        }
        if (opts.experimentalPriority === true) {
          process.env[PRIORITY_FLAG] = '1';
        }
        if (opts.prSummary === true && process.env[POLICY_FLAG] !== '1') {
          throw new Error(`--pr-summary requires ${POLICY_FLAG}=1`);
        }
        if (opts.experimentalCiReports === true) {
          process.env[CI_REPORTS_FLAG] = '1';
        }
        const wantsCiReport =
          opts.githubAnnotations !== undefined || opts.junit !== undefined || opts.gitlab !== undefined;
        if (wantsCiReport && process.env[CI_REPORTS_FLAG] !== '1') {
          throw new Error(
            `--github-annotations, --junit, and --gitlab require ${CI_REPORTS_FLAG}=1`,
          );
        }

        const result = await scan({
          cwd: resolve(path),
          modules,
          includeHome: opts.includeHome === true,
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
          experimentalPolicy: process.env[POLICY_FLAG] === '1',
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
        if (opts.githubAnnotations !== undefined) {
          await writeFile(resolve(opts.githubAnnotations), renderGithubAnnotations(result), 'utf8');
        }
        if (opts.junit !== undefined) {
          await writeFile(resolve(opts.junit), renderJunitReport(result), 'utf8');
        }
        if (opts.gitlab !== undefined) {
          await writeFile(resolve(opts.gitlab), renderGitlabCodeQuality(result), 'utf8');
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

        if (opts.prSummary === true) {
          io.out(renderPrSummary(result.findings));
        } else {
          io.out(
            opts.json === true
              ? renderJsonReport(result)
              : renderConsoleReport(result, { all: opts.all === true }),
          );
        }

        if (result.policy !== undefined && result.policy.errors.length > 0) {
          for (const message of result.policy.errors) {
            io.err(`fullshield: ${message}`);
          }
          process.exitCode = 1;
        }
        if (result.suppressionErrors !== undefined && result.suppressionErrors.length > 0) {
          for (const message of result.suppressionErrors) {
            io.err(`fullshield: ${message}`);
          }
          process.exitCode = 1;
        }
        const failOn = failOnOverride ?? result.policy?.failOn ?? result.config.failOn;
        if (result.findings.some((f) => failsCi(f, failOn))) {
          process.exitCode = 1;
        }
      } catch (error) {
        io.err(formatCliError(error));
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
          if (result.notice !== undefined) io.out(result.notice);
        } else if (opts.apply !== true) {
          io.out('Dry run. Re-run with --apply to write safe fixes.');
        }
      } catch (error) {
        io.err(formatCliError(error));
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
        io.err(formatCliError(error));
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
        io.err(formatCliError(error));
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
        const doc = await buildSbom(resolve(path), {
          includeReach: process.env.FULLSHIELD_EXPERIMENTAL_SBOM_REACH === '1',
        });
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
        io.err(formatCliError(error));
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
        io.err(formatCliError(error));
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
        io.err(formatCliError(error));
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
        io.err(formatCliError(error));
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
        io.err(formatCliError(error));
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
        io.err(formatCliError(error));
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
        io.err(formatCliError(error));
        process.exitCode = 2;
      }
    });

  program
    .command('explain')
    .description('Print one finding from a scan JSON file (requires FULLSHIELD_EXPERIMENTAL_EXPLAIN=1)')
    .argument('<id>', 'finding id or a prefix of at least 6 characters')
    .option('--from <file>', 'scan --json file')
    .action(async (id: string, opts: { from?: string }) => {
      try {
        if (process.env.FULLSHIELD_EXPERIMENTAL_EXPLAIN !== '1') {
          throw new Error('explain requires FULLSHIELD_EXPERIMENTAL_EXPLAIN=1');
        }
        if (opts.from === undefined) throw new Error('explain needs --from <scan.json> (FULLSHIELD_EXPERIMENTAL_EXPLAIN)');
        const raw = JSON.parse(await readFile(opts.from, 'utf8')) as { findings?: unknown };
        if (!Array.isArray(raw.findings)) throw new Error('explain --from is not scan JSON (FULLSHIELD_EXPERIMENTAL_EXPLAIN)');
        const text = await explainFinding({
          cwd: process.cwd(),
          id,
          findings: raw.findings as Parameters<typeof explainFinding>[0]['findings'],
        });
        io.out(text);
      } catch (error) {
        io.err(formatCliError(error));
        process.exitCode = 2;
      }
    });

  program
    .command('deps-diff')
    .description('Compare a lockfile at a git ref with the working tree (requires FULLSHIELD_EXPERIMENTAL_DEPS_DIFF=1)')
    .argument('<ref>', 'git ref to read with git show')
    .argument('[path]', 'project directory', '.')
    .option('--json', 'print JSON')
    .option('--fail-on <severity>', 'exit 1 when an introduced advisory is at or above this severity')
    .option('--offline', 'use the OSV cache only')
    .action(async (ref: string, path: string, opts: { json?: boolean; failOn?: string; offline?: boolean }) => {
      try {
        if (process.env.FULLSHIELD_EXPERIMENTAL_DEPS_DIFF !== '1') {
          throw new Error('deps-diff requires FULLSHIELD_EXPERIMENTAL_DEPS_DIFF=1');
        }
        const cwd = resolve(path);
        const previous = await lockAtRef(cwd, ref);
        let currentText = '';
        try {
          currentText = await readFile(join(cwd, previous.file), 'utf8');
        } catch {
          currentText = '';
        }
        const before = packagesFromLock(previous.file, previous.text);
        const after = packagesFromLock(previous.file, currentText);
        const changes = diffLockedPackages(before.packages, after.packages, after.direct);
        const moved = after.packages.filter((pkg) =>
          changes.some((change) => change.name === pkg.name && change.change !== 'removed' && change.newVersion === pkg.version),
        );
        const hits = await queryOsv(moved, {
          cacheDir: join(cwd, 'osv-cache'),
          offline: opts.offline === true,
        });
        const introduced = hits.flatMap((hit) =>
          hit.vulns.map((vuln) => ({
            name: hit.pkg.name,
            version: hit.pkg.version,
            id: vuln.id,
            severity: osvSeverity(vuln),
          })),
        );
        const added = changes.filter((change) => change.change === 'added');
        const ages = [];
        for (const change of added) {
          let published: string | undefined;
          let installScripts: 'yes' | 'no' | 'unknown' = 'unknown';
          try {
            const raw: unknown = JSON.parse(await readFile(registryCachePath(join(cwd, 'osv-cache'), change.name), 'utf8'));
            const facts = releaseFactsFromCache(raw, change.newVersion);
            published = facts.publishedAt;
            if (facts.hasInstallScript === true) installScripts = 'yes';
            if (facts.hasInstallScript === false) installScripts = 'no';
          } catch {
            published = undefined;
          }
          ages.push({
            name: change.name,
            version: change.newVersion,
            age: releaseAgeLabel(published, Date.now()),
            installScripts,
          });
        }
        const report = { changes, introduced, ages };
        io.out(JSON.stringify(report, null, 2));
        if (opts.failOn !== undefined) {
          const threshold = parseFailOn(opts.failOn);
          if (introduced.some((item) => meetsThreshold(item.severity, threshold))) process.exitCode = 1;
        }
      } catch (error) {
        io.err(formatCliError(error));
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
        io.err(formatCliError(error));
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
        io.err(formatCliError(error));
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
        io.err(formatCliError(error));
        process.exitCode = 2;
      }
    });

  program
    .command('host')
    .description('Experimental host SSH exposure check (Linux only; FULLSHIELD_EXPERIMENTAL_HOST=1)')
    .option('--experimental-host', 'required: enable experimental host OpenSSH check')
    .option('--json', 'machine-readable JSON output')
    .option('--offline', 'do not contact OSV; use upstream version fallback')
    .option('--attempt-threshold <n>', 'auth.log Timeout-before-authentication per-IP flag threshold', '5')
    .action(async (opts: {
      experimentalHost?: boolean;
      json?: boolean;
      offline?: boolean;
      attemptThreshold?: string;
    }) => {
      try {
        if (opts.experimentalHost !== true) {
          throw new Error('host requires --experimental-host (FULLSHIELD_EXPERIMENTAL_HOST=1)');
        }
        process.env.FULLSHIELD_EXPERIMENTAL_HOST = '1';
        const parsed = Number(opts.attemptThreshold ?? '5');
        const attemptThreshold = Number.isFinite(parsed) && parsed >= 0 ? parsed : 5;
        const result = await runHostCheck({
          experimental: true,
          offline: opts.offline === true,
          attemptThreshold,
        });
        const note =
          'Detection/reporting only. FullShield does not block, patch, or harden OS services.';
        if (result.skipped) {
          if (opts.json === true) {
            io.out(JSON.stringify({ skipped: true, reason: result.reason, findings: [], note }, null, 2));
          } else {
            io.out(`FullShield host: skipped (${result.reason}) ${note}`);
          }
          return;
        }
        if (opts.json === true) {
          io.out(
            JSON.stringify(
              {
                skipped: false,
                findings: result.findings,
                exposure: result.exposure,
                mitigated: result.mitigated,
                versionVulnerable: result.versionVulnerable,
                note,
              },
              null,
              2,
            ),
          );
        } else {
          io.out(`FullShield host — ${result.findings.length} finding(s)`);
          for (const f of result.findings) io.out(`  [${f.severity}] ${f.ruleId} ${f.message}`);
          if (result.findings.length === 0) {
            io.out('No HOST-SSH findings. FullShield does not stop OS or SSH exploits.');
          }
        }
        if (result.findings.some((f) => meetsThreshold(f.severity, 'high'))) process.exitCode = 1;
      } catch (error) {
        io.err(formatCliError(error));
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
        io.err(formatCliError(error));
        process.exitCode = 2;
      }
    });

  program
    .command('vex')
    .description('Experimental VEX from reachability (FULLSHIELD_EXPERIMENTAL_VEX=1)')
    .argument('[path]', 'project directory', '.')
    .option('--format <format>', 'openvex | cyclonedx', 'openvex')
    .option('--out <file>', 'write to this file instead of stdout')
    .action(async (path: string, opts: { format?: string; out?: string }) => {
      try {
        if (process.env.FULLSHIELD_EXPERIMENTAL_VEX !== '1') {
          throw new Error('vex requires FULLSHIELD_EXPERIMENTAL_VEX=1');
        }
        const format = opts.format ?? 'openvex';
        if (format !== 'openvex' && format !== 'cyclonedx') {
          throw new Error(`unsupported VEX format "${format}" (valid: openvex, cyclonedx)`);
        }
        const cwd = resolve(path);
        const result = await scan({ cwd, modules: ['deps'] });
        let name = 'app';
        let version = '0.0.0';
        try {
          const { readFile } = await import('node:fs/promises');
          const pkg = JSON.parse(await readFile(join(cwd, 'package.json'), 'utf8')) as {
            name?: unknown;
            version?: unknown;
          };
          if (typeof pkg.name === 'string') name = pkg.name;
          if (typeof pkg.version === 'string') version = pkg.version;
        } catch {
          // package.json optional
        }
        const { buildVex, validateCycloneDxVex, validateOpenVex } = await import('../vex/index.js');
        const doc = buildVex(result.findings, format, { name, version });
        const errors = format === 'cyclonedx' ? validateCycloneDxVex(doc) : validateOpenVex(doc);
        if (errors.length > 0) throw new Error(`invalid VEX: ${errors.join('; ')}`);
        const json = JSON.stringify(doc, null, 2);
        if (opts.out !== undefined) {
          await writeFile(resolve(opts.out), json, 'utf8');
          io.out(`Wrote ${format} VEX to ${opts.out}`);
        } else {
          io.out(json);
        }
      } catch (error) {
        io.err(formatCliError(error));
        process.exitCode = 2;
      }
    });

  program
    .command('diff')
    .description('Experimental comparison of two scan --json files (FULLSHIELD_EXPERIMENTAL_DIFF=1)')
    .argument('<before>', 'earlier scan JSON')
    .argument('<after>', 'later scan JSON')
    .option('--experimental-diff', 'enable this command (FULLSHIELD_EXPERIMENTAL_DIFF=1)')
    .option('--json', 'print the machine diff')
    .option('--out <file>', 'write the machine diff to this file')
    .option('--fail-on <severity>', 'exit 1 when an added finding is at or above this severity', 'high')
    .action(
      async (
        beforePath: string,
        afterPath: string,
        opts: { experimentalDiff?: boolean; json?: boolean; out?: string; failOn?: string },
      ) => {
        try {
          if (opts.experimentalDiff === true) process.env[DIFF_FLAG] = '1';
          if (!diffEnabled()) throw new Error(`diff requires ${DIFF_FLAG}=1`);
          const failOn = parseFailOn(opts.failOn ?? 'high');
          let beforeText: string;
          let afterText: string;
          try {
            beforeText = await readFile(resolve(beforePath), 'utf8');
            afterText = await readFile(resolve(afterPath), 'utf8');
          } catch {
            throw new Error('cannot read diff input');
          }
          const diff = diffScans(parseScanDocument(beforeText), parseScanDocument(afterText));
          const json = JSON.stringify(diff, null, 2);
          if (opts.out !== undefined) await writeFile(resolve(opts.out), json, 'utf8');
          io.out(opts.json === true ? json : renderDiffText(diff));
          if (addedFails(diff, failOn)) process.exitCode = 1;
        } catch (error) {
          io.err(formatCliError(error));
          process.exitCode = 2;
        }
      },
    );

  program
    .command('doctor')
    .description('Report Node, lockfile, cache, flags, config, and whether OSV is offline')
    .argument('[path]', 'project directory', '.')
    .option('--offline', 'do not describe OSV as allowed to use the network')
    .option('--config <file>', 'explicit config file')
    .action(async (path: string, opts: { offline?: boolean; config?: string }) => {
      try {
        io.out(await runDoctor(resolve(path), opts));
      } catch (error) {
        io.err(formatCliError(error));
        process.exitCode = 2;
      }
    });

  return program;
}
