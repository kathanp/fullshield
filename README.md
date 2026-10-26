# FullShield

**v2.0.1.** One install for Node.js/TypeScript backends: detect → classify → report → notify → fix → gate (CI `--fail-on` + runtime monitor). It does not stop attacks by itself.

**Headline: dependency reachability.** A lockfile CVE is not the same as an unused package. FullShield classifies each OSV hit as `reachable` (imported and called), `imported-not-called` (−1), `reachable-via-dependency` (lockfile path from an imported direct dep — **severity kept**, path shown, e.g. `express > body-parser > qs`), `not-imported` (−2, only when no such path exists), or `reachability-unknown` (severity kept) when the lockfile format has no parsed dependency edges. DevDependency-only vulns are `info` with a `dev-only` note unless production sources import the package. Pair it with `fullshield sbom --format cyclonedx`.

```bash
npx fullshield scan
npx fullshield scan --json --fail-on high
npx fullshield scan --sarif fullshield.sarif
```

2.0.1 is the version of this tree. The stable contract is [docs/stability.md](docs/stability.md). The 1.0.1 release moved values that only experimental flags produce out of Stable. Experimental flags stay off unless you set them. Do not treat a scan as a penetration test. Reviewed recall for untouched apps is not published. The stored Next.js cold scan is 71.7 seconds, above the 60-second target.

**Supported runtime is Node.js >= 22.13.** `package.json` `engines` and `doctor` enforce that floor. `node:sqlite` runs without `--experimental-sqlite` from 22.13.0 (the module is still experimental and is loaded only by history/confirm, not by `--import` register).

Contributor quality gate: [docs/QUALITY.md](docs/QUALITY.md) (`npm run quality`). It does not change scan results.

## Coverage map

| Layer | Covered by |
|---|---|
| Code vulnerabilities | `sast` (intra-function + cross-file taint, depth 5) |
| Dependencies (now + new CVEs later) | `deps` (OSV + **reachability**) + `watch` |
| Secrets | `secrets` + `scan --staged` / pre-commit hook |
| App/server config | `config` |
| Live app-layer signals | `runtime` (`fullshield/runtime/express` or `/fastify`) in **monitor** mode; **experimental** RASP sink hooks via `--import fullshield/runtime/register` (fail-open; not a prevention guarantee) |
| Edge/DDoS layer | `edge` checks that a CDN/WAF **exists** (headers only). Actual DDoS mitigation is the CDN. |
| AI assist (opt-in, **experimental**) | `scan --ai explain` and `fix --ai` only. Off by default: zero AI network calls. Explain never shows a verdict. Triage and logic hunter are not shipped. |
| LLM-app code (opt-in, **experimental**) | `LLM-001`–`LLM-005` (`FULLSHIELD_EXPERIMENTAL_LLM=1`). Phrase/AST heuristics, not a jailbreak defense. |
| Supply-chain install (opt-in, **experimental**) | `fullshield install` — static only; never executes packages. |
| Exploit confirm (opt-in, **experimental**) | `fullshield confirm` — localhost / 127.0.0.1 / FullShield-started container only. |
| Editor MCP (opt-in, **experimental**) | `fullshield mcp --stdio` — read-only; `propose_fix` returns diffs, never writes. |
| MCP client/server config (opt-in, **experimental**) | `MCP-001`–`MCP-005` (`FULLSHIELD_EXPERIMENTAL_MCPCFG=1`). Home-dir configs only with `scan --include-home`. |
| Threat model / dashboard (opt-in, **experimental**) | STRIDE+Mermaid sketch; dashboard binds 127.0.0.1 and locks `Host`. |
| Compliance / IaC (opt-in, **experimental**) | Mapping is **not a certification or audit**. IaC is ~10 high-value rules, not a full IaC scanner. |
| Remediation agent (opt-in, **experimental**) | Localhost mock GitHub API + local git only. Never merges, never pushes to `main`/`master`. |
| Response DLP (opt-in, **experimental**) | `shieldGuard({ dlp: { mode: 'monitor' \| 'mask' \| 'block' } })` with `FULLSHIELD_EXPERIMENTAL_DLP=1`. Inspects outgoing JSON/text (≤64 KB). Not a DLP product. |
| Policy / PR summary (opt-in, **experimental**) | `fullshield.policy.json` + `scan --pr-summary` (`FULLSHIELD_EXPERIMENTAL_POLICY=1`). Not an OPA/Kyverno substitute. |
| Host OpenSSH (opt-in, **experimental**) | `fullshield host --experimental-host` (`FULLSHIELD_EXPERIMENTAL_HOST=1`). Linux only. **What it does NOT do:** FullShield does not stop OS or SSH exploits. |

## What it detects (Core)

- **SAST:** SQL/NoSQL injection, command injection, path traversal, `eval`/`new Function`/`vm`, SSRF, open redirects, JWT `decode`/`none`, weak crypto, prototype pollution, XSS (`res.send` HTML and `<%-` / `{{{` templates), missing auth middleware (low confidence). `AI-INJECT-001` is a **basic phrase heuristic** (three exact comment phrases: "ignore previous", "mark as safe", "AI reviewer") — not a prompt-injection defense.
- **Secrets:** AWS, Stripe, GitHub, Slack, Google, AI keys, PEM keys, DB URLs with passwords, hardcoded JWT secrets, committed `.env`.
- **Deps:** OSV vulnerabilities with reachability (`reachable` / `imported-not-called` / `reachable-via-dependency` / `not-imported` / `reachability-unknown`), `dev-only` info for unused devDependencies, lockfile deprecation notices, typosquat-suspicious *direct* dependency names. `DEPS-MALICIOUS-001` for OSV `MAL-` / malicious-classified advisories is **always critical** and is never downgraded (install scripts run at `npm install`). `DEPS-NOLOCK-001` when there is a manifest but no lockfile; exact `package.json` pins are still queried.
- **Config:** missing helmet, `express.json()` without a limit, CORS `*` + credentials, auth routes without a rate limiter, `err.stack` leaks, risky Dockerfiles, install scripts.

## Non-goals (honesty is a feature)

- Does **not** find business-logic or authorization bugs (CSRF, missing ownership checks). It can flag routes with no auth middleware as *suspicious*. `SAST-IDOR-001` is an experimental low-confidence hint (`FULLSHIELD_EXPERIMENTAL_IDOR=1`) and does not fail CI.
- Does **not** replace a penetration test.
- Does **not** auto-delete code. `fix --apply` writes patches on a clean git tree. If project tests fail, each written file is restored from a byte-for-byte snapshot taken before the write — never `git checkout --`. `--force` on a dirty tree still refuses to touch files that have uncommitted changes.
- v1 is **JS/TS only**. Other languages are out of scope.
- Cross-file taint follows `require`/`import` and method calls up to 5 hops and records a `trace` (also SARIF `codeFlows`). Nested closures and some dynamic dispatch are still missed.
- Runtime v1 is **signature-based** (payload regex + rate limit + body-size guard). It is a **stopgap monitor**, not a WAF. Prefer **`mode: 'monitor'`** in production until you have measured false-positive rate. Sink-hooking RASP is **experimental** (off by default; see below) and does not claim to prevent attacks.
- Only scan hosts and repos you own or are authorized to test.
- **Experimental features are off by default and are not product claims:**
  - RASP / virtual patches / honeytokens / threat auto-block: fail-open hooks; decoy-route hits are low and never auto-block; auto-block is opt-in (shared-IP / NAT risk).
  - `install` / supply-chain: static heuristics only; never a substitute for `npm audit` policy or a malware sandbox.
  - `confirm`: harmless canaries on localhost only; fail-open (`unconfirmed` is not a pass).
  - MCP / LLM-app rules: editor glue and shallow AST/phrase checks. Not a prompt-injection or tool-abuse guarantee. `MCP-001`–`MCP-005` (`FULLSHIELD_EXPERIMENTAL_MCPCFG=1`) scan client configs and MCP server code; they do not inspect running MCP traffic and never scan `$HOME` unless `scan --include-home`.
  - Threat-model / incremental / dashboard: a route sketch and a local history UI. Not a STRIDE workshop or a hosted SOC.
  - `report --compliance` / `iac`: evidence-style mapping and a short IaC ruleset. **Not a certification or audit.**
  - `agent`: opens PRs against a **mock/localhost API and a local git remote**. It never talks to real GitHub, never merges, never pushes to protected branches.
  - `vex` / worm / overrides (`FULLSHIELD_EXPERIMENTAL_VEX=1`): static heuristics and reachability-backed VEX only. Default `scan` does not emit `SUPPLY-WORM-001` / `SUPPLY-WORKFLOW-001`. Overrides are **unsafe** (`fix --unsafe`). Apply writes `package.json` and prints `run npm install`; it does not edit the lockfile. Never claim `not_affected` unless reachability proves `not-imported`.
  - Response DLP (`FULLSHIELD_EXPERIMENTAL_DLP=1`): inspects outgoing JSON/text for secret patterns, stack traces, internal IPs/hostnames, Luhn card numbers, and bulk emails. Pattern matching only; size-capped; not a DLP or tokenization product.
  - Policy / `--pr-summary`: CI exceptions with expiry, not a general policy engine. PR comments are deterministic (no AI) and are not posted to GitHub or GitLab.
  - `host` (`FULLSHIELD_EXPERIMENTAL_HOST=1`): Linux-only OpenSSH exposure report. **What it does NOT do:** FullShield does not stop OS or SSH exploits. Detection and reporting only. It does not block, patch, or harden OS services.

## Known limitations

- Platforms: Linux, macOS, and Windows on Node >= 22.13. Quoted filenames in dirty-tree tests are POSIX-only (Windows forbids `"` in names).
- `node:sqlite` is loaded only by history/confirm, not by `--import fullshield/runtime/register`. Dashboard closes every handle in `try/finally` (Windows cannot delete an open `history.db`).
- FullShield does not stop OS or SSH exploits (including regreSSHion). It scans Node/TS apps you own.
- Extra classes (ReDoS, deserialization, XXE, upload, cookie flags, CSRF, mass assignment, timing compare, hash cost, GraphQL limits, `trust proxy` + IP rate limit) run only with `FULLSHIELD_EXPERIMENTAL_CLASSES=1` or `scan --experimental-classes`. ReDoS is a same-file static quantifier check. CSRF looks for `csurf` or `sameSite: 'strict'|'lax'` in that file.
- Git history, client-bundle, and live credential checks are **experimental** (`FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1`). Default `scan` is unchanged. `--verify-secrets` never runs without `--i-own-these-credentials`; AWS checks without a signing secret key report `unknown`.
- Dependency capability profiles (`FULLSHIELD_EXPERIMENTAL_CAPABILITIES=1`) read installed files only. They do not run install scripts. `deps-diff` reports a new capability only when the previous package integrity is already cached. Source files over 1 MB are skipped. A comment or string that names an API can count as that capability.
- Fix verification (`FULLSHIELD_EXPERIMENTAL_FIX_VERIFY=1`) re-scans the patched file and its direct importers. A line shift of an unchanged finding is not a new finding. A comment-only patch stays `does-not-remove`. A missing OSV cache entry for the planned version stays `does-not-remove` and is not treated as a cleared advisory. The check does not run project tests or `npm install`.

Experimental RASP structure-change scoring on the vendored PayloadsAllTheThings corpus (not a claim that live attacks are blocked):

- **SQL 42/42.** Quote-breakouts inside `'…'` (`' OR 1=1 --`, `'; DROP TABLE x; --`) are detected. Payloads `"-"`, `" "`, `"&"`, `"^"` were moved to the benign set: they stay inside one single-quoted string token and are not exploitable in that sink.
- **Shell 45/45.** Quote-breakouts that close a quoted `ls` argument (`'; id; '`, `"; id; "`) are detected. Payloads `";id;"`, `';id;'`, `"|id|"`, `'|id|'` were moved to the benign set: `;` / `|` stay inside one quoted word.

Path 51/51 and SSRF 39/39 on the same corpus. Benign corpus stays 0 blocked. Prefer `mode: 'monitor'`.

These fixtures are self-authored. Numeric SQL (`WHERE id = ` + input), ORM raw-query APIs (Prisma/Sequelize/Knex/TypeORM/Drizzle/`$where`), and template-literal shell (`exec(\`…${x}\`)`, `spawn('sh', ['-c', …])`, execa `shell: true`, zx `$.raw`) are covered in the attack corpus. Those ORM and shell sinks are part of the default scan. `FULLSHIELD_EXPERIMENTAL_SAST_GAPS` and `scan --experimental-sast-gaps` stay accepted and do not turn them off. Mongo `$where` strings are **stable** SAST (Juice Shop track-order / reviews).

In-scope public-bench patterns we still do not claim (one line each):

- Swig `{{ name }}` is `SAST-XSS-001` only when the view engine is Swig and that name is tainted from `req` or a database read. `{{csrftoken}}` and unrendered templates are not findings. Handlebars `{{ }}` stays unflagged. `autoescape: false` is still a finding.
- Juice Shop track-order XSS — server returns `res.json`; we do not treat JSON fields as HTML sinks.
- Juice Shop `url.includes(allowedUrl)` — weak allowlist helper is not a redirect sink; we flag `res.redirect(tainted)`.
- Juice Shop `{ _id: req.body.id }` — flagged as `SAST-NOSQLI-001` (medium) unless coerced (`String()`/`Number()`/`Boolean()`), schema-validated, or mongo-sanitize is applied. Same for goof `User.find({ password: req.body.password })`.
- Juice Shop `data/static/codefixes/*` — six `SAST-NOSQLI-001` hits are copies of the challenge fixes. They stay. There is no special-case exclusion for that directory.
- `DEPS-VULN-001` — when an OSV hit exists, the finding is attributed to the `package.json` name line; `--offline-safe` on a cache-less clone still emits no OSV hits (`package.json:N` will not match).
- `SUPPLY-PROV-001` (`FULLSHIELD_EXPERIMENTAL_PROVENANCE=1`) — registry provenance, publisher, and release-age signals from `registry.npmjs.org` only. Offline with an empty cache stays unknown. These signals are not a malicious-package claim.
- DVNA calculator “stack leak” — that line is `mathjs.eval` (`SAST-EVAL-001`), not `err.stack`.
- Worker-pool timings from `node bench/perf.mjs --measure` on 2026-10-16 (`bench/perf-baseline.json`): next.js finished all 5 samples (cold p50 71.7s, warm 71.5s, incremental 70.6s, peak RSS 788 MB, every sample under 1 GB). nest cold p50 9.1s, warm 9.3s, peak 815 MB; undici cold p50 8.4s, warm 8.4s, peak 563 MB. nest and undici still miss the 5s incremental target (nest 9.4s, undici 8.2s). These are local timings, not a recall claim.
- Real-world precision is not sampled. Nine of the ten pins in `bench/realworld.json` have finding counts in `BENCHMARK.md`. next.js produced no JSON. No false-positive rate is claimed.

Public-app in-scope detection on **unreviewed** ground truth (`"reviewed": false` in `bench/*/ground-truth.json`). These are not product recall claims. Matching is class + file + line ±3. Helmet comment-only line attribution is not counted.

- Seen holdout `snyk-labs/nodejs-goof` @ `add14ba59e98240d9e00a235dd7d42cd61ae9912`: 10/11 in-scope (unreviewed). Not a recall gain; this app was used to find engine gaps.
- Seen holdout `cr0hn/vulnerable-node` @ `d68f2a3c9277ece2c2feb9976052033bdecd7fbe`: 9/12 in-scope (unreviewed). Re-scored after the authorized NoSQL filter-value rule; not a recall gain.
- NodeGoat 5/7, Juice Shop 10/12, DVNA 9/10 (same unreviewed files; deps TPs need an OSV cache hit under `--offline-safe`).

Precision in [`BENCHMARK.md`](BENCHMARK.md) is self-triaged, unverified. Unsure counts on that run: NodeGoat 4, Juice Shop 39, DVNA 5, goof 4, vulnerable-node 29.

## Quick start

```bash
npm i -D fullshield
npx fullshield init
npx fullshield scan --fail-on high
```

## Commands you can run

No extra flag. These are the stable commands:

```bash
npx fullshield scan
npx fullshield scan --json --fail-on high
npx fullshield scan --sarif fullshield.sarif
npx fullshield scan --markdown report.md
npx fullshield scan --html report.html
npx fullshield scan --offline
npx fullshield scan --staged
npx fullshield fix
npx fullshield fix --apply
npx fullshield init
npx fullshield notify
npx fullshield sbom --format cyclonedx --out sbom.json
npx fullshield watch
npx fullshield edge https://app.example.com
npx fullshield doctor
npx fullshield doctor --offline
```

`scan` runs deps, secrets, sast, and config. `fix` prints patches and writes only with `--apply` on a clean git tree. `init` writes config, CI, and a pre-commit hook. `notify` sends the last scan to Slack, a webhook, or SMTP. `sbom` writes CycloneDX 1.5. `watch` alerts only on a new OSV hit. `edge` checks one URL you pass for a CDN, HTTPS, headers, and `/.env` or `/.git`. `doctor` prints Node, the lockfile, the cache, flags set to `1`, and whether OSV may use the network.

Each command below exits with `FS-E###` until its flag is exactly `1`. None of them run on a default `scan`.

```bash
FULLSHIELD_EXPERIMENTAL_DIFF=1 npx fullshield diff before.json after.json
FULLSHIELD_EXPERIMENTAL_INGEST=1 npx fullshield ingest report.sarif
FULLSHIELD_EXPERIMENTAL_EXPLAIN=1 npx fullshield explain <id> --from .fullshield/last-scan.json
FULLSHIELD_EXPERIMENTAL_DEPS_DIFF=1 npx fullshield deps-diff origin/main
FULLSHIELD_EXPERIMENTAL_CAPABILITIES=1 npx fullshield deps --capabilities
FULLSHIELD_EXPERIMENTAL_SUPPLY=1 npx fullshield install .
FULLSHIELD_EXPERIMENTAL_CONFIRM=1 npx fullshield confirm
FULLSHIELD_EXPERIMENTAL_MCP=1 npx fullshield mcp --stdio
FULLSHIELD_EXPERIMENTAL_HONEY=1 npx fullshield honey init
FULLSHIELD_EXPERIMENTAL_PLATFORM=1 npx fullshield threat-model
FULLSHIELD_EXPERIMENTAL_PLATFORM=1 npx fullshield report --serve
FULLSHIELD_EXPERIMENTAL_COMPLIANCE=1 npx fullshield report --compliance pci
FULLSHIELD_EXPERIMENTAL_IAC=1 npx fullshield iac
FULLSHIELD_EXPERIMENTAL_AGENT=1 npx fullshield agent
FULLSHIELD_EXPERIMENTAL_DEV=1 npx fullshield dev
FULLSHIELD_EXPERIMENTAL_VEX=1 npx fullshield vex
FULLSHIELD_EXPERIMENTAL_HOST=1 npx fullshield host --experimental-host
FULLSHIELD_EXPERIMENTAL_NPM_AUDIT_DIFF=1 npx fullshield npm-audit-diff --file audit.json
FULLSHIELD_EXPERIMENTAL_SPDX=1 npx fullshield sbom --format spdx --out sbom.spdx.json
```

`diff` compares two `scan --json` files and does not scan. `ingest` reads local SARIF, npm audit, OSV-Scanner, and Semgrep JSON and does not run those tools. `explain` prints one finding and never a verdict. `deps-diff` compares a lockfile at a git ref with the working tree. `deps --capabilities` profiles installed packages and does not run their scripts. `install` is static. `confirm` sends harmless canaries to localhost only. `mcp` is read-only. `agent` talks to a localhost mock and a local git remote. `host` reports OpenSSH exposure on Linux and does not block, patch, or harden sshd. `npm-audit-diff` compares an `npm audit --json` file you already have with scan findings. It does not run `npm`.

Default `scan` npm coverage is the lockfile `name@version`, one OSV query, import-level reachability, and a Levenshtein-1 typosquat check on direct names. Deeper npm checks are off until you set one `FULLSHIELD_EXPERIMENTAL_NPM_<NAME>=1` flag. A flag reads the lockfile, `package.json`, `.npmrc`, or a cache file already on disk. It does not install the package, run a lifecycle script, or fetch a tarball. Registry packument checks read `cacheDir/registry/` only. Tarball checks read a tarball cache only. The groups are lockfile truth, manifest and project policy, registry metadata, tarball bytes, lifecycle script text, package names, and the dependency graph. Advisory helpers for range type, withdrawn rows, CVSS, alias collapse, and package URLs do not change default OSV findings. Core and breadth rule ids are indexed in [`rules/README.md`](rules/README.md). The npm-depth ids are the `rules/DEPS-*.md` files for those flags.

Library:

```ts
import { scan } from 'fullshield';
const result = await scan({ cwd: process.cwd() });
```

Runtime (does not load the scanner). **Signature-based stopgap — monitor mode recommended.**

```ts
import express from 'express';
import { shieldGuard } from 'fullshield/runtime/express';

const app = express();
app.use(shieldGuard({ mode: 'monitor', authRoutes: ['/login'] }));
```

**Experimental Frontier (off by default):** `FULLSHIELD_EXPERIMENTAL_VPATCH=1` + `scan --emit-virtual-patches`; `FULLSHIELD_EXPERIMENTAL_HONEY=1` + `fullshield honey init`.

**Experimental CI reports (off by default):** `FULLSHIELD_EXPERIMENTAL_CI_REPORTS=1` or `scan --experimental-ci-reports`, then `--github-annotations`, `--junit`, and `--gitlab`. Default console and `--json` output stay the same. Critical and high become GitHub `error` commands and JUnit failures. Medium is a GitHub warning and a JUnit failure. Low and info are GitHub notices and JUnit skips. GitLab severities are info, minor, major, critical, and blocker.

**Experimental scan diff (off by default):** `FULLSHIELD_EXPERIMENTAL_DIFF=1` or `fullshield diff --experimental-diff <before.json> <after.json>`. Compares two `scan --json` files. The match ignores the line number. It does not scan and does not decide which findings are real. Added findings at or above `--fail-on` (default high) exit 1. Baseline `suppressions` need an owner, a reason, and an expiry. The spec is [`docs/history/ADVANCED-SPEC.md`](docs/history/ADVANCED-SPEC.md).

**Experimental ingest (off by default):** `FULLSHIELD_EXPERIMENTAL_INGEST=1` or `fullshield ingest --experimental-ingest <file...>`. Reads local SARIF 2.1.0, OSV-Scanner JSON, `npm audit --json`, and Semgrep JSON. It does not run those tools and does not fetch. Severity stays the tool's severity (`moderate` and Semgrep `WARNING` are stored as medium; the original token is `externalSeverity`). `fullshieldPriority` is not set.

**Experimental RASP** (Frontier, off by default): structure-change sink hooks via `node --import fullshield/runtime/register app.js` or `import 'fullshield/runtime/auto'` as the first import. Enable only with `FULLSHIELD_EXPERIMENTAL_RASP=1`. Default mode is `monitor` (events only). `FULLSHIELD_RASP_MODE=block` throws on structure-changing SQL/shell/path/NoSQL/SSRF/prototype input. Hooks **fail open**: a hook error logs `RASP-FAIL-OPEN-001` and the original call proceeds. Do not use block mode in production until you have measured the benign corpus on your app.

`npm run bench` reports `inspect()` p50/p95 (must stay under 1ms) and full Express request overhead p50/p95 with the middleware on the stack.

**Experimental response DLP** (off by default): `FULLSHIELD_EXPERIMENTAL_DLP=1` plus `shieldGuard({ dlp: { mode: 'monitor' | 'mask' | 'block' } })`. Without the flag, `shieldGuard` is inspect-only on the incoming request (unchanged). `mask` replaces matches; `block` returns HTTP 500 with `{ error: 'internal error' }`. Events go to `onEvent`. Bodies over 64 KB are skipped and counted. Prefer `monitor` until you have measured the benign corpus on your app.

## Commands

| Command | Purpose |
|---|---|
| `scan` | Run deps, secrets, sast, config. `--json`, `--sarif`, `--markdown`, `--html`, `--fail-on`, `--offline`, `--staged`, `--update-baseline`. `--ai explain` is **experimental** (off by default; explanation text only, never a verdict). `--pr-summary` is **experimental** (`FULLSHIELD_EXPERIMENTAL_POLICY=1`): deterministic Markdown of new findings versus baseline for GitHub/GitLab PR comments (no AI; links to rule docs). |
| `diff` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_DIFF=1`). Compare two `scan --json` files. `--fail-on` applies to added findings only. |
| `ingest` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_INGEST=1`). Read local SARIF, npm audit, OSV-Scanner, and Semgrep JSON and dedupe. Does not run those tools. |
| `fullshield.policy.json` | **Experimental** policy-as-code (`FULLSHIELD_EXPERIMENTAL_POLICY=1`): `requiredModules`, per-rule `severityOverrides`, `failOn` per branch, and `exceptions` that require `owner`, `reason`, and ISO `expires`. Expired exceptions fail CI. Exceptions without owner or expiry are rejected. |
| `fix` | Dry-run patches (unsafe suggestions included). `--apply` writes only `safe: true` patches on a clean git tree. `--unsafe` is required for `helmet()` insertion and secret → `process.env` replacement. `--force` skips files with uncommitted changes. `--ai` is **experimental**: drafts a verified, reviewable diff for findings without a rule-based fix (never auto-merged). |
| `init` | Config + GitHub/GitLab CI + pre-commit hook |
| `notify` | Slack / generic webhook / SMTP summary of the last scan |
| `sbom` | CycloneDX 1.5 JSON (`--format cyclonedx`, `--out file`). Experimental SPDX 2.3 (`FULLSHIELD_EXPERIMENTAL_SPDX=1` or `--experimental-spdx`, `--format spdx`, `--sbom-timestamp`, `--cyclonedx-out`). Licenses are copied from package data only. |
| `watch` | Rescan dependencies; alert (webhook / exit 1) only on **new** OSV hits vs last scan. `init` writes a daily GitHub Action. |
| `edge` | GET/HEAD posture check on a URL you pass: CDN/WAF, HTTPS redirect, security headers, `/.env` / `/.git` exposure. No crawl, no payloads. |
| `install` | **Experimental** install-guard (`FULLSHIELD_EXPERIMENTAL_SUPPLY=1`). Static analysis only; never runs package scripts. Registry reads are `registry.npmjs.org` only. |
| `deps --capabilities` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_CAPABILITIES=1`). Static capability profile of installed dependencies (process, network, fs write, env, eval, native addon, dynamic require, install scripts, obfuscation) including transitive packages. `deps-diff` adds `newCapabilities` only with the same flag. `SUPPLY-CAP-001` is a `deps.capabilityPolicy` deny hit and is never in the default scan. |
| `confirm` | **Experimental** exploit confirm (`FULLSHIELD_EXPERIMENTAL_CONFIRM=1`). localhost / 127.0.0.1 / FullShield-started container only. Harmless canaries only. |
| `mcp` | **Experimental** MCP server (`FULLSHIELD_EXPERIMENTAL_MCP=1`). Official SDK stdio: `fullshield mcp --stdio`. Requires optional peers `@modelcontextprotocol/sdk` and `zod` (`npm i -D @modelcontextprotocol/sdk zod`); missing peers print an install hint, not a stack dump. Read-only tools: `scan`, `get_findings`, `explain_finding`, `propose_fix` (diff only, never writes), `verify_fix` (temp copy). |
| `honey init` | **Experimental** honeytokens (`FULLSHIELD_EXPERIMENTAL_HONEY=1`). Decoy routes are **low** severity and aggregated per IP; only use of a canary **credential** is critical. Auto-block is off unless `threatAutoBlock` is set (shared-IP / NAT risk; max duration applies). Decoys are fake values added to `.gitignore`. |
| `threat-model` | **Experimental** STRIDE + Mermaid (`FULLSHIELD_EXPERIMENTAL_PLATFORM=1`). |
| `report --serve` | **Experimental** local dashboard (`FULLSHIELD_EXPERIMENTAL_PLATFORM=1`). Binds **127.0.0.1 only** and rejects any `Host` other than localhost/127.0.0.1 (DNS rebinding). No state-changing GET. |
| `report --compliance pci` | **Experimental** evidence-style mapping (`FULLSHIELD_EXPERIMENTAL_COMPLIANCE=1`). **Not a certification or audit.** |
| `iac` | **Experimental** light IaC (`FULLSHIELD_EXPERIMENTAL_IAC=1`): GHA, Terraform, Kubernetes, docker-compose. Not a full IaC scanner. |
| `agent` | **Experimental** remediation agent (`FULLSHIELD_EXPERIMENTAL_AGENT=1`). Mock/localhost GitHub API + local git remote only — never a real network. Never merges, never pushes to `main`/`master`. `--max-prs` (default 3). |
| `scan --changed` / `--since` | **Experimental** incremental scan (`FULLSHIELD_EXPERIMENTAL_PLATFORM=1`). |
| `scan --diff` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_DIFFSCAN=1` or `--experimental-diffscan`). Scans git-changed JS/TS files, the files they import by a relative literal, and the files that import them the same way. One hop. A sink in an unchanged importer still reports when the changed file returns the request value. A git failure is `FS-E018` and does not scan the rest of the tree. Off, or `scan` without `--diff`, matches today's scan. |
| `scan --experimental-flow2` | **Stable.** One object field (`obj.a`) and one nested function are part of the default scan. `FULLSHIELD_EXPERIMENTAL_FLOW2` and this flag stay accepted and do not turn that off. `obj.b` stays clean. `JSON.parse` does not clear taint. Handlebars `{{ }}`, `res.json`, and a `url.includes` allowlist helper stay unflagged. |
| `dev` | **Experimental** save loop (`FULLSHIELD_EXPERIMENTAL_DEV=1`). Watches the project and prints only new and resolved findings. |
| `scan --experimental-sast-gaps` | **Stable.** ORM raw SQL, `spawn('sh', ['-c'])`, execa `shell: true`, and zx `$.raw` are part of the default scan. `FULLSHIELD_EXPERIMENTAL_SAST_GAPS` and this flag stay accepted and do not turn that off. |
| `scan --experimental-ldap` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_LDAP=1`). `SAST-LDAP-001`: `search`, `compare`, `modify`, or `bind` on an LDAP client when the filter or DN is request data. A string-literal filter does not fire. Off by default. |
| `scan --experimental-cors-reflect` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_CORSREFLECT=1`). `CONFIG-CORS-002`: `Access-Control-Allow-Origin` is the request `Origin` and credentials are allowed on that response. A fixed origin does not fire. `origin: '*'` with credentials stays `CONFIG-CORS-001`. Off by default. |
| `scan --experimental-rsc` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_RSC=1`). `DEPS-RSC-001`: a lockfile resolves `react-server-dom-webpack`, `react-server-dom-parcel`, or `react-server-dom-turbopack` to 19.0.0, 19.1.0, 19.1.1, or 19.2.0. A canary or any other version does not fire. No lockfile means no finding. Off by default. |
| `scan --experimental-cooldown` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_COOLDOWN=1`). `CONFIG-COOLDOWN-001`: `.npmrc`, `pnpm-workspace.yaml`, `.yarnrc.yml`, or `bunfig.toml` is present and the release-age gate is missing or shorter than three days. npm is days, pnpm is minutes, yarn is a duration, bun is seconds. A project with none of those four files does not fire. Off by default. |
| `scan --experimental-import-implant` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_IMPORTIMPLANT=1`). `SUPPLY-IMPLANT-001`: `setup_bun.js` or `bun_environment.js` is in the scan, named by a preinstall/install/postinstall script, or present under `node_modules` (capped at 2000 manifests, no symlinks). Off by default. |
| `scan --experimental-ver-inflate` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_VERINFLATE=1`). `DEPS-VERINFLATE-001`: a lockfile version whose major is 9999 or greater, or whose patch is 999 or 9999. `1.2.3` does not fire. Off by default. |
| `scan --experimental-agent-rules` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_AGENTRULES=1`). `AGENT-UNICODE-001`, `AGENT-INJECT-001`, `AGENT-EXFIL-001`, and `AGENT-SHELL-001` on `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `.cursor/rules/**`, `.windsurf/rules/**`, and `SKILL.md` under `.cursor/`, `.claude/`, or `.agents/`. A short guideline with none of those markers does not fire. Off by default. |
| `scan --experimental-agent-spawn` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_AGENTSPAWN=1`). `SAST-AGENTSPAWN-001`: `exec`, `execSync`, `spawn`, `spawnSync`, `Bun.spawn`, `Bun.spawnSync`, or `new Deno.Command` launches `claude`, `codex`, or `gemini` with `--dangerously-skip-permissions`, `--permission-mode bypassPermissions`, or `--yolo` in the same call. The program without the flag does not fire. Off by default. |
| `scan --experimental-mcp-poison` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_MCPPOISON=1`). JSON that contains `mcpServers`. `MCP-006` asks for a password, token, secret, or API key. `MCP-007` puts `ignore previous` or a shell marker in a schema default. `MCP-008` repeats one tool name on two servers in one file. One server with a literal description does not fire. `MCP-001`–`MCP-005` stay on `FULLSHIELD_EXPERIMENTAL_MCPCFG`. Off by default. |
| `scan --experimental-vite-fs` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_VITEFS=1`). `CONFIG-VITEFS-001`: a Vite config sets `server.fs.strict` to false or `server.fs.allow` to `/` or a drive root. Omitted `server.fs` does not fire. Off by default. |
| `scan --experimental-host-poison` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_HOSTPOISON=1`). `SAST-HOST-001`: `Host` or `X-Forwarded-Host` is copied into an absolute URL passed to `redirect`, `location`, `sendMail`, or a `Location` header. A fixed host does not fire. Off by default. |
| `scan --experimental-markup` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_MARKUP=1`). `SAST-MARKUP-001`: `markdown-it` is constructed with `html: true` and `render` is called with request data, or `marked` / `marked.parse` is called with request data. The file must import that package. Literal markdown does not fire. Off by default. |
| `scan --experimental-trust-host` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_TRUSTHOST=1`). `SAST-TRUSTHOST-001`: a file that mentions `next-auth`, `@auth/`, or `NextAuth` sets `trustHost: true`. `false` or omitted does not fire. Off by default. |
| `scan --experimental-deep` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_DEEP=1`). Extra matches on the existing rules: `res.end` when the body contains HTML, `http.request` / `https.request` option objects, `Bun.file` and `fs` `glob` / `opendir`, `location`, `jwt.verify` with an empty or non-literal algorithm list, and `Object.assign` / `assign`. Off by default. Default `scan --json` is unchanged for these. |
| `scan --experimental-crlf` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_CRLF=1`). `SAST-CRLF-001`: request data used as the value of `setHeader`, `append`, `header`, `set`, or a `writeHead` header object. A literal value does not fire. A status code alone does not fire. Off by default. |
| `scan --experimental-mail` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_MAIL=1`). `SAST-MAIL-001`: `nodemailer`, `@sendgrid/mail`, or `mailgun.js` copies request data into `to`, `cc`, `bcc`, `subject`, `from`, `replyTo`, `html`, or `text`. A literal field does not fire. Off by default. |
| `scan --experimental-formula` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_FORMULA=1`). `SAST-FORMULA-001`: request data passed to `stringify`, `write`, `writeToPath`, or `format` from `csv-stringify`, `fast-csv`, `json2csv`, or `csv`, or written to a `.csv` path. A literal row does not fire. Off by default. |
| `scan --experimental-browser` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_BROWSER=1`). Sets the existing browser flag. `SAST-BROWSER-001`: `puppeteer`, `puppeteer-core`, `playwright`, or `@playwright/test` passes request data to `goto`, `setContent`, or `pdf`. A literal URL or HTML body does not fire. Phase 101 browser rules stay on this same flag. Off by default. |
| `scan --experimental-dynimport` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_DYNIMPORT=1`). `SAST-DYNIMPORT-001`: `import()` called with request data. A string-literal specifier does not fire. Off by default. |
| `scan --experimental-frameworks` | **Experimental** Next.js / NestJS / Hono / Koa taint sources and AUTH (`FULLSHIELD_EXPERIMENTAL_FRAMEWORKS=1`). Default `scan` is unchanged. Runtime adapters: `fullshield/runtime/koa`, `fullshield/runtime/hono` (optional peers). |
| `scan --experimental-classes` | **Experimental** extra vuln classes: ReDoS, deser, XXE, upload, cookies, CSRF, mass assignment, timing compare, hash cost, GraphQL, trust-proxy (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`). Default `scan` is unchanged. |
| `scan` crypto v2 | **Experimental** (`FULLSHIELD_EXPERIMENTAL_CRYPTO2=1`). `SAST-CIPHER-001`, `SAST-CIPHER-002`, `SAST-RSA-001`, and `SAST-JWT-002`: ECB and deprecated ciphers, literal IVs, literal symmetric keys, short RSA or secp192 keys, and JWTs with no expiry or a short HMAC secret. Off by default. |
| `scan` Electron | **Experimental** (`FULLSHIELD_EXPERIMENTAL_ELECTRON=1`). `CONFIG-ELECTRON-001` through `CONFIG-ELECTRON-003`: unsafe `webPreferences`, `shell.openExternal` without an https check, and a remote `loadURL` without navigation guards. Only when `electron` is installed. Off by default. |
| `scan` vendored JS | **Experimental** (`FULLSHIELD_EXPERIMENTAL_VENDORED=1`). `DEPS-VENDORED-001`: known-vulnerable copies of jquery, bootstrap, lodash, and the other libraries in `models/vendored.json`, matched by banner or `VERSION` only. Off by default. |
| `scan` template injection | **Experimental** (`FULLSHIELD_EXPERIMENTAL_SSTI=1`). `SAST-SSTI-001`: tainted template source for the engines in `models/ssti.json`. Off by default. |
| `scan` webhooks | **Experimental** (`FULLSHIELD_EXPERIMENTAL_WEBHOOK=1`). `SAST-WEBHOOK-001`: Stripe, GitHub, Slack, Shopify, and Twilio handlers with no verifier. Off by default. |
| `scan` session fixation | **Experimental** (`FULLSHIELD_EXPERIMENTAL_SESSION2=1`). `SAST-SESSION-002`: login writes the session without `regenerate`. `req.login` counts only for passport 0.6.0 or newer. Off by default. |
| `scan` log secrets | **Experimental** (`FULLSHIELD_EXPERIMENTAL_LOGLEAK=1`). `SAST-LOGLEAK-001`: credential headers, auth-route bodies, and secret-named identifiers written to a logger. Off by default. |
| `scan` Next.js boundary | **Experimental** (`FULLSHIELD_EXPERIMENTAL_NEXT=1`). `SAST-NEXT-001`, `CONFIG-NEXT-001`, `CONFIG-NEXT-002`, and `SECRET-NEXTPUB-001`. Off by default. |
| `scan` browser JS | **Experimental** (`FULLSHIELD_EXPERIMENTAL_BROWSER=1`). `SAST-DOMXSS-001`, `SAST-REACT-001`, `SAST-POSTMSG-001`, and `SAST-TOKENSTORE-001`. Server taint rules skip browser sources. Off by default. |
| `scan` unfixed deps | **Experimental** (`FULLSHIELD_EXPERIMENTAL_HEALTH=1`). `DEPS-UNFIXED-001`: a production dependency with no fixed version whose last publish is older than 730 days. Off by default. |
| `scan` IDOR hints | **Experimental** (`FULLSHIELD_EXPERIMENTAL_IDOR=1`). `SAST-IDOR-001`: a low-confidence hint. `source: rule` does not fail CI. Off by default. |
| `scan` TLS verification | **Experimental** (`FULLSHIELD_EXPERIMENTAL_TLS=1`). `SAST-TLS-001` and `SAST-TLS-002`: `rejectUnauthorized: false`, `checkServerIdentity` returning undefined, and `NODE_TLS_REJECT_UNAUTHORIZED=0` in source, Docker, compose, package scripts, and `.env` files. Test paths are low. A `NODE_ENV !== 'production'` guard is medium. Off by default. |
| `scan` credential files | **Experimental** (`FULLSHIELD_EXPERIMENTAL_CREDFILES=1`). `SECRET-FILE-002` through `SECRET-FILE-007`: `.npmrc` auth literals, Docker `config.json` auth, kubeconfig tokens, Terraform state, service-account keys, and private key files. Masked. Off by default. `--staged` includes them. |
| `scan --history` / `--bundle <dir>` / `--verify-secrets` | **Experimental** secrets advanced (`FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1` or `scan --experimental-secrets-adv`). History streams `git log -p` (first-introduced commit, still-at-HEAD). Bundle scans `dist/` `.next/static` `build/` for browser-exposed keys including `NEXT_PUBLIC_*`/`VITE_*`. `--verify-secrets` is never default and is **not** in generated CI templates; it needs `--i-own-these-credentials` and only hits read-only identity endpoints (AWS STS GetCallerIdentity, GitHub `GET /user`, Stripe `GET /v1/balance`, Slack `auth.test`). Results: `live` / `revoked` / `unknown`. The key is never logged. |
| `scan` provenance | **Experimental** (`FULLSHIELD_EXPERIMENTAL_PROVENANCE=1`). `SUPPLY-PROV-001` (medium) when an installed version drops `dist.attestations`, is published by a user absent from the previous 10 versions, or is inside the Phase 62 release-age window. `registry.npmjs.org` only. `--offline` uses the registry cache; a miss stays unknown and is not a finding. Not a malicious-package claim. |
| `vex` | **Experimental** OpenVEX / CycloneDX VEX from reachability (`FULLSHIELD_EXPERIMENTAL_VEX=1`). `not_affected` + `vulnerable_code_not_in_execute_path` only when reachability is `not-imported`; otherwise `under_investigation`. Never guessed. Also enables worm/workflow indicators, unsafe `dependency-override` proposals, and a provenance coverage score. Apply writes `package.json` and prints `run npm install`; it does not edit the lockfile. |
| `scan --experimental-mcpcfg` | **Experimental** MCP client/server config rules `MCP-001`–`MCP-005` (`FULLSHIELD_EXPERIMENTAL_MCPCFG=1`). Default `scan` emits no `MCP-*` IDs. |
| `scan --include-home` | **Experimental** also scan MCP configs under the user home (`.cursor/mcp.json`, `.vscode/mcp.json`, `.mcp.json`, Claude Desktop). Requires `FULLSHIELD_EXPERIMENTAL_MCPCFG=1`. Never implied. |
| `host --experimental-host` | **Experimental** Linux-only OpenSSH exposure check (`FULLSHIELD_EXPERIMENTAL_HOST=1`). Reports `HOST-SSH-001`..`003` (version, no `LoginGraceTime 0`, auth timeout attempts). Refuses without `--experimental-host`. Default `scan` is unchanged. Skips with an info message on macOS, Windows, containers without sshd, and PaaS. **What it does NOT do:** FullShield does not stop OS or SSH exploits. |
| `explain` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_EXPLAIN=1`). `fullshield explain <id> --from <scan.json>` prints one finding. It never shows a verdict. |
| `deps-diff` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_DEPS_DIFF=1`). Compare the lockfile at a git ref with the working tree. |
| `npm-audit-diff` | **Experimental** (`FULLSHIELD_EXPERIMENTAL_NPM_AUDIT_DIFF=1`). `fullshield npm-audit-diff --file audit.json --from scan.json` compares a local `npm audit --json` file with scan findings. Without `--from` it reads `.fullshield/last-scan.json`. It does not run `npm audit`. |
| `scan` npm depth | **Experimental** (`FULLSHIELD_EXPERIMENTAL_NPM_<NAME>=1`). Lockfile, manifest, `.npmrc`, registry cache, tarball cache, lifecycle script text, package names, and graph checks from phases 108–242. Off unless that flag is `1`. No install, no script execution, no tarball download. |
| `fix --experimental-fix-verify` | **Experimental** fix verification (`FULLSHIELD_EXPERIMENTAL_FIX_VERIFY=1`). Each `fix` patch and each `explain` diff is applied in memory and re-scanned. `introduces-finding` is never written. `does-not-remove` needs `--force-unverified`. Dependency version checks read the OSV cache only. |

Inline ignore (reason required): `// fullshield-ignore SAST-SQLI-001: reviewed`

## Rule docs

See [`rules/README.md`](rules/README.md).

## Benchmarks

Public-app detection results (OWASP NodeGoat, Juice Shop, DVNA, seen holdouts `snyk-labs/nodejs-goof` and `cr0hn/vulnerable-node`) live in [`BENCHMARK.md`](BENCHMARK.md). Those ground-truth files are still `"reviewed": false`. Holdout numbers are listed under Known limitations and are on unreviewed ground truth. Precision in `BENCHMARK.md` is self-triaged, unverified. Self-authored fixture notes live in [`benchmarks/REPORT.md`](benchmarks/REPORT.md). Live Ollama smoke results (not CI) live in [`benchmarks/AI-REPORT.md`](benchmarks/AI-REPORT.md).

### Cursor MCP (`mcp.json`)

```json
{
  "mcpServers": {
    "fullshield": {
      "command": "npx",
      "args": ["fullshield", "mcp", "--stdio"],
      "env": { "FULLSHIELD_EXPERIMENTAL_MCP": "1" }
    }
  }
}
```

`propose_fix` returns a diff only. It never writes your tree.

## Developer commands

```bash
npx fullshield doctor
npx fullshield doctor --offline
npx fullshield scan --debug
```

`doctor` prints the Node version, lockfile, cache directory, experimental flags that are set to `1`, whether `fullshield.config.json` parses, and whether OSV is allowed to use the network. `--offline` skips that network. CLI failures use `FS-E###` codes. The message stays the same. A stack is printed only with `--debug`.

Default console prints shown rows only, capped at 20. A dependency advisory is shown when it is `DEPS-MALICIOUS-001`, or when it is `DEPS-VULN-001`, not dev-only, and reachability is reachable, symbol-reachable, via a dependency, or unknown. Severity and confidence do not show a dependency row. SAST, secrets, and config are shown when severity is high or critical, or confidence is high. Shown dependency findings are one row per package. `--all` prints every finding. JSON, SARIF, Markdown, HTML, the baseline, and `--fail-on` stay the full list. On the 2026-10-18 offline-safe recount, grouped rows were NodeGoat 36, goof 63, juice-shop 49, dvna 14, and vulnerable-node 41. Ground truth is still `"reviewed": false`.

Experimental taint propagation (`FULLSHIELD_EXPERIMENTAL_TAINT_V2=1`) and the parse pool (`FULLSHIELD_PARSE_POOL=1`) are off by default. Symbol reachability runs only when an OSV advisory lists `affected_functions`. Advisories without that list keep the import-level class.

`COMPARISON.md` is not linked here. The mapping has not been reviewed. A local semgrep / osv-scanner / npm audit run is in that file, and it is not a recall claim. Benchmark numbers stay in [`BENCHMARK.md`](BENCHMARK.md) with the unreviewed label.

See [`SECURITY.md`](SECURITY.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), and [`RELEASING.md`](RELEASING.md).

## License

MIT
