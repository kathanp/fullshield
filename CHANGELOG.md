# Changelog

All notable changes to FullShield are documented here.

## 0.3.0 — 2026-10-16

### Default scan changes

Stable finding keys changed. CI baselines may need `--update-baseline`. This is not a recall claim. Ground truth was not edited and nothing was marked reviewed.

Before (`bench/snapshots/0.1.3.json` / previous `HEAD.json`, `scan --json --offline-safe`):

| app | findings |
|---|---|
| vulnerable-app | 35 |
| clean-app | 0 |
| nodegoat | 379 |
| juice-shop | 105 |
| dvna | 23 |
| goof | 354 |
| vulnerable-node | 61 |

After (`bench/snapshots/HEAD.json`, same flags):

| app | findings |
|---|---|
| vulnerable-app | 35 |
| clean-app | 0 |
| nodegoat | 256 |
| juice-shop | 105 |
| dvna | 23 |
| goof | 271 |
| vulnerable-node | 61 |

Unique `(ruleId, file, line, severity)` keys did not change. The count drop is duplicate keys: several versions of one package and advisory shared one package.json line and one severity. In-scope matches on the unreviewed ground truth stayed at NodeGoat 5/7 (plus 1 line-only), Juice Shop 10/12, DVNA 9/10, goof 11/11, vulnerable-node 9/12. See `bench/snapshots/DIFF.txt`.

- Dependency advisories are one finding per package name + advisory. Every retained dependency path is listed on that finding. Severity is the highest of the grouped versions. Rules were not removed and severities were not lowered to cut the count.
- SAST findings with the same rule id and sink line collapse to one.
- Default walk skips `node_modules`, `dist`, `build`, `.next`, `coverage`, `vendor`, `vendored`, `third_party`, `third-party`, `compiled`, and `*.min.js`. Set `"defaultExcludes": false` or replace the list with `"excludes"`.
- Files over `sast.maxFileBytes` (default 1 MB), and files that contain NUL bytes, are reported as `SAST-SKIP-001` (info) instead of being skipped silently.
- Repos with more than 4000 source files are parsed one file at a time so the AST is released before the next file. Cross-file taint on those repos runs in batches of 150. Smaller repos, including the in-scope bench apps, keep the previous all-files parse.
- The parse pool keeps an LRU of 64 ASTs, caps workers (default 2, explicit max 4), and caps each worker heap (`FULLSHIELD_PARSE_WORKER_MB`, default 512).

### Experimental CI reports

Off unless `FULLSHIELD_EXPERIMENTAL_CI_REPORTS=1` or `scan --experimental-ci-reports`. Default `scan` and `--json` are unchanged.

- `--github-annotations` writes GitHub Actions workflow commands. Critical and high are `error`, medium is `warning`, low and info are `notice`.
- `--junit` writes JUnit XML. Medium and above are failures. Low and info are skipped. An empty scan is one passing testcase.
- `--gitlab` writes a GitLab Code Quality report. Severities map to info, minor, major, critical, and blocker.

### Experimental scan diff

Off unless `FULLSHIELD_EXPERIMENTAL_DIFF=1` or `fullshield diff --experimental-diff`. It compares two `scan --json` files. It does not scan and does not use the network.

- Match key is rule id, file, severity, and the snippet or message. The line number is not part of the key. Two findings with that same text stay two results. A line shift is a move. One shared finding id with a different message is a move. Duplicate ids are not paired.
- Added findings at or above `--fail-on` (default `high`) exit 1. AI findings, moves, and removals do not. The human report lists at most 20 added findings.
- Diff matching and the GitLab fingerprint ignore the line number. A changed message with the same id is a move.
- Console, JSON, SARIF, Markdown, HTML, GitHub, JUnit, and GitLab reports mask AWS, GitHub, Stripe, and Slack token shapes before writing them.
- `.fullshield-baseline.json` may list `suppressions` with `ruleId`, `owner`, `reason`, and ISO `expires`. Expired or incomplete rows do not hide findings and fail the scan.
- `FULLSHIELD_EXPERIMENTAL_IAC=1` also flags `github.event` inside `run:` steps and a `pull_request_target` job that checks out pull-request code.
- Lockfile helpers flag `http://` or a non-registry `resolved` URL, and a resolved entry with no integrity hash.
- `scan --history` stops after 500 commits (`FULLSHIELD_HISTORY_MAX`, max 5000). When older commits are left out, the console and the JSON metadata say `scanned N of M commits`. History snippets are masked.
- `FULLSHIELD_EXPERIMENTAL_LICENSE=1` flags an installed direct dependency whose package.json says GPL or AGPL.

### Node 20

- `engines` is `>=20.11`. `node:sqlite` is the only runtime API that needs Node 22.13. History storage prints that requirement. Confirm does not import `node:sqlite`. RASP sqlite hooks no-op when the module is missing. CI runs Node 20, 22, and 24.

## 0.2.6 — 2026-10-16

- v0.2.5 reached staging with a fresh token, then sigstore threw `TLOG_CREATE_ENTRY_ERROR` because Rekor already had that transparency-log entry (HTTP 409). npm 12.2.0 leaves `fetchOnConflict` off, so the publish stopped. Staging now turns that on before loading the publisher, and gives the Rekor request 120 seconds. It still refuses to publish without provenance.

## 0.2.5 — 2026-10-16

- The publish probe saved the GitHub OIDC token, then verify ran for 24 minutes. npm rejected that expired token with HTTP 401 when staging started. Staging now requests a new token immediately before the exchange, and the probe does not save one. The job pins npm 12.2.0.

## 0.2.4 — 2026-10-16

- Publish installs npm 12. `npm pack --json` is now an object, and the pack budget was parsing the inner `files` array. It reads the pack entry from either shape.

## 0.2.3 — 2026-10-16

- The publish checkout was shallow, so `semver-check` could see only the tag being released. That job now fetches full history and tags before comparing versions.

## 0.2.2 — 2026-10-16

- `v0.2.1` failed typecheck before staging. The baseline-tag test now types its tag argument.

## 0.2.1 — 2026-10-16

- `v0.2.0` was tagged and the publish job failed before staging. `semver-check` treated that tag as the previous release and compared `0.2.0` to itself. The check now skips a tag that points at HEAD.

## 0.2.0 — 2026-10-16

Phases 36–45 ship in this version. `0.3.0` and `0.4.0` were not tagged.

### Phase 36 — provenance and semver

- Publish refuses to stage without provenance. `0.1.3` has no attestation because the stage retried after a sigstore 409. The publish job now polls `dist.attestations` and fails if it stays empty.
- `scripts/semver-check.mjs`, `scripts/pack-budget.mjs`, and `scripts/provenance-gate.mjs`.
- TypeORM `class User extends BaseEntity` plus `User.find` is not `SAST-NOSQLI-001` when the file does not import `typeorm`. A bare `User.find(req.body)` is unchanged.
- Default-scan snapshots are `bench/snapshots/0.1.1.json`, `bench/snapshots/0.1.3.json`, and `bench/snapshots/HEAD.json`. Finding keys are `ruleId`, `file`, `line`, `severity`. Published `0.1.3` and this tree match: vulnerable-app 35, clean-app 0, nodegoat 379, juice-shop 105, dvna 23, goof 354, vulnerable-node 61. `0.1.1` has no `--offline-safe` flag, so that snapshot is `scan --json` only. It differs. The printed diff is `bench/snapshots/DIFF.txt`. That file is not a human approval.

### Phases 37–45

- Holdout registry, three untouched apps, and review sheets. Those apps were not scanned.
- Comparison harness. One local run is in `COMPARISON.md`: semgrep 1.180.0, osv-scanner 2.7.0, npm 11.19.0. Mapped class buckets stayed empty. osv-scanner returned no JSON for juice-shop and dvna (no lockfile at those pins). Commercial scanners were not executed. This is not a recall claim.
- Symbol reachability when an advisory's `affected_functions` list is present. Advisories without that list stay on the import-level class. `DEPS-MALICIOUS-001` is not downgraded.
- Taint propagation for callbacks, `call`/`apply`, `Object.assign`, spread, `this` fields, and closures behind `FULLSHIELD_EXPERIMENTAL_TAINT_V2=1`. Default scan does not enable it.
- Ten real-world repos are pinned. Nine produced finding counts in `BENCHMARK.md`. next.js aborted with a JavaScript heap out of memory and has no count. Nothing is labeled, so precision is not sampled.
- Parse pool behind `FULLSHIELD_PARSE_POOL=1`. Measured times are in `bench/perf-baseline.json`. next.js aborted (SIGABRT) on every sample. nest and undici finished under the cold and warm targets and missed the 5s incremental target.
- Promotion report lists every experimental flag as unmet. Nothing was promoted.
- `fullshield doctor`, `FS-E###` error codes, and console output capped at 10 findings.
- GitHub Actions in the project workflows are pinned by commit SHA. Scorecard and CodeQL workflows are added. Scorecard is v2.5.0 from `ghcr.io` because `gcr.io` refused the pull. A tag workflow attaches a CycloneDX SBOM to the GitHub Release.
- `node scripts/repro-build.mjs --check` on 2026-10-16: 26 `dist` files hashed the same across two builds.

## 0.1.3 — 2026-10-15

### Phase 35 — experimental host SSH exposure check

- `fullshield host --experimental-host` (`FULLSHIELD_EXPERIMENTAL_HOST=1`) reports OpenSSH CVE-2024-6387 (regreSSHion) exposure on Linux: distro package version via `dpkg-query` / `rpm` / `apk` (not `ssh -V`), OSV distro advisories with upstream fallback, `LoginGraceTime 0`, `ss -ltn` listen address, and optional auth.log timeout patterns. Detection/reporting only — no block, patch, or harden. Skips macOS, Windows, containers without sshd, and PaaS. Command refuses without `--experimental-host`. Default `scan` is unchanged.

### Phase 34 — policy-as-code + PR summary

- Experimental `fullshield.policy.json` (`FULLSHIELD_EXPERIMENTAL_POLICY=1`): required modules, per-rule severity overrides, `failOn` per git/CI branch, and exceptions that require `owner`, `reason`, and ISO `expires`. Expired exceptions fail CI with a clear message. Exceptions without owner or expiry are rejected. Schema is validated with the optional `zod` peer (lazy-imported; not a hard dependency).
- `scan --pr-summary`: deterministic Markdown for GitHub/GitLab PR comments listing new findings versus baseline (no AI), with links to rule docs. Uses existing baseline/diff.
- Default `scan` without the flag or a policy file is unchanged.

### Phase 33 — MCP configuration security (experimental)

- `FULLSHIELD_EXPERIMENTAL_MCPCFG=1` / `scan --experimental-mcpcfg` scans MCP client configs (`.cursor/mcp.json`, `.vscode/mcp.json`, `.mcp.json`, Claude Desktop) and MCP server code. Default `scan` emits no `MCP-*` IDs.
- `MCP-001` inline secrets (high), `MCP-002` unpinned `npx` / `@latest` (medium), `MCP-003` shell/exec or unrestricted fs-write tools without an allowlist (medium), `MCP-004` tool-description instruction injection / hidden / zero-width characters (high), `MCP-005` remote MCP over `http://` (medium).
- Home-dir configs are scanned only with `scan --include-home` (never implied). No network.
- Model-provided MCP tool arguments are taint sources when the flag is on. Optional `guardTools(tools, { allow, confirm })` deny-lists dangerous tools, requires confirm for writes/payments, and logs every call.

### Phase 32 — experimental response DLP

- Optional `shieldGuard({ dlp: { mode: 'monitor' | 'mask' | 'block' } })` inspects outgoing JSON/text (size-capped at 64 KB) for secret patterns (same regexes as the secrets module), stack traces, internal IPs/hostnames, Luhn card numbers, and bulk emails on a one-email route.
- Behind `FULLSHIELD_EXPERIMENTAL_DLP=1`. Without the flag, `shieldGuard` and default `scan` are unchanged. `mask` replaces matches; `block` returns 500 `{ error: 'internal error' }`. Events go to `onEvent`. Over-cap bodies are skipped and counted.

### Phase 31 — supply chain, advanced + VEX

- Experimental (`FULLSHIELD_EXPERIMENTAL_VEX=1` / `scan --experimental-vex`): self-replicating worm indicators (`SUPPLY-WORM-001`) and workflow/git-hook/CI writes (`SUPPLY-WORKFLOW-001`). Default `scan` is unchanged.
- Transitive `FixProposal.kind = 'dependency-override'` (unsafe) when the parent has no fixed release. Writes npm `overrides` / pnpm `pnpm.overrides` / yarn `resolutions` into `package.json` and prints `run npm install`. The lockfile is not edited.
- Provenance coverage score (% of deps with provenance; unknown is not counted as present) with history-DB trend helpers.
- `fullshield vex --format openvex|cyclonedx` from reachability. `not_affected` + `vulnerable_code_not_in_execute_path` only when reachability is `not-imported`; otherwise `under_investigation`. Never guessed.

### Phase 30 — secrets, advanced (experimental)

- `scan --history` streams `git log -p`, dedupes by blob hash, and reports first-introduced commit + still-at-HEAD. Respects baseline and suppressions.
- `scan --bundle <dir>` scans `dist/`, `.next/static`, and `build/` for browser-exposed keys, including `NEXT_PUBLIC_*` / `VITE_*` secret-shaped values (`SECRET-BUNDLE-001`).
- `--verify-secrets` is opt-in, never default, never in generated CI templates. Requires `--i-own-these-credentials`. Read-only identity endpoints only (AWS STS GetCallerIdentity, GitHub `GET /user`, Stripe `GET /v1/balance`, Slack `auth.test`). Results: `live` \| `revoked` \| `unknown`. Never logs the key.
- Behind `FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1` / `scan --experimental-secrets-adv`. CLI flags do nothing useful without that flag. Default `scan` does not emit Phase-30-only rule IDs.

### Phase 29 — new vulnerability classes

- Experimental extra SAST/config classes (`FULLSHIELD_EXPERIMENTAL_CLASSES=1` / `scan --experimental-classes`): ReDoS, insecure deserialization, XXE, unrestricted upload, cookie flags, CSRF, mass assignment, timing-safe compare, password-hash cost, GraphQL introspection/depth, and `trust proxy` + IP rate limits. Default `scan` is unchanged.

- Publish CI uses `npm publish --provenance --access public` (no staged-manifest edits). The unpublished `v0.1.2` tag was deleted.
- CI: push to `next` runs `verify` on ubuntu-24.04 × Node 24 only. The full 6-job matrix (and the non-blocking `bench` job) runs on pull requests to `main` and on push to `main`. Required checks on `main` stay the six matrix jobs.

### Phase 28 — framework coverage

- Experimental Next.js / NestJS / Hono / Koa taint sources and AUTH (`FULLSHIELD_EXPERIMENTAL_FRAMEWORKS=1` / `scan --experimental-frameworks`). Default `scan` is unchanged.
- Runtime adapters `fullshield/runtime/koa` and `fullshield/runtime/hono` (optional peers; not required dependencies).

### NoSQL constructed-filter values

**New stable findings — may change CI results; use `--update-baseline`:**

- `SAST-NOSQLI-001` — request input used as a Mongo filter value (e.g. `{ password: req.body.password }`) at medium confidence, unless the value is coerced (`String()` / `Number()` / `Boolean()`), schema-validated (zod / joi / yup `.parse`), or `mongo-sanitize` / `express-mongo-sanitize` is applied. Fires only on MongoDB/mongoose receivers (file imports `mongodb`/`mongoose`, `collection.find` / `*Collection`, or a PascalCase model). Never Sequelize, Prisma, TypeORM, Knex, Drizzle, or unknown receivers.

`cr0hn/vulnerable-node` is now a seen holdout (no longer untouched).

### Phase 26c — engine gaps from the goof holdout

- Taint: method-call return inherits receiver taint; same-file helper parameters are seeded from tainted arguments; imported functions that return taint taint their call sites.
- Path: `extractAllTo` / `extractAll` / `extract` on a tainted archive object (zip-slip receiver).
- Config: missing helmet is attributed to the `express()` line when no commented-out helmet is present.
- Deps: OSV hits on direct dependencies are attributed to the `package.json` name line when a hit exists (still no invented advisories under `--offline-safe`).
- Multipart uploads: `req.files` is a taint source.
- `nodejs-goof` is a seen holdout. `cr0hn/vulnerable-node` is an untouched holdout scanned once. Precision in `BENCHMARK.md` is labeled self-triaged, unverified.

### Phase 26b — stable public-bench misses

**New stable findings — may change CI results; use `--update-baseline`:**

- `SAST-NOSQLI-001` — Mongo `$where` with a tainted string
- `SAST-REDIRECT-001` — destructured `{ query }` as a taint source (`res.redirect(query.to)`)
- `SAST-CRYPTO-001` — `md5(tainted)` used as a reset token
- `SAST-XSS-001` — `autoescape: false`
- `CONFIG-HELMET-001` — commented-out `helmet` (line-attributed; not a new detection on NodeGoat)
- `CONFIG-DIRLIST-001` — `serveIndex()` directory listing
- `SECRET-SESSION-001` — hardcoded `express-session` secret

Remaining in-scope misses (Swig `{{ }}` template line, JSON XSS, `includes()` allowlist, nested `{ _id: req.body.id }`, deps lockfile/offline, DVNA calc vs eval) stay in README Known limitations. Ground truth files were not edited to improve numbers.

Holdout: `bench:public` also clones pinned `snyk-labs/nodejs-goof`. Rules are not tuned from that app.

### Phase 27 — SAST + RASP coverage gaps

- RASP treats extra tokens in unquoted numeric SQL (`WHERE id = 1 OR 1=1`) as a structure change; a single number (`42`) stays allowed.
- Experimental SAST sinks (`FULLSHIELD_EXPERIMENTAL_SAST_GAPS=1` / `scan --experimental-sast-gaps`): Prisma `$queryRawUnsafe` / `$executeRawUnsafe` / `Prisma.raw`, Knex `raw`/`whereRaw`/`orderByRaw`, TypeORM `createQueryBuilder().where(concat)`, Drizzle `sql.raw`, mongoose `$where`, `spawn('sh', ['-c'])`, execa `shell: true`, zx `$.raw` / `{ quote: false }`. Prisma `$queryRaw` tagged templates and default zx `$` are not flagged. Default `scan` is unchanged.
- RASP load-time hooks for `@prisma/client`, `sequelize`, `knex`, `typeorm`, `drizzle-orm`, and mongoose `$where`.
- Attack corpus adds ≥10 cases each for `numeric-sql`, `orm-raw`, and `template-shell`. Benign corpus still 0 blocked.

### Phase 26 — public benchmark harness

- `npm run bench:public` clones pinned OWASP NodeGoat, Juice Shop, and DVNA SHAs, scans with `--json --offline-safe`, and writes `BENCHMARK.md`. Ground truth is exhaustive vs each app’s official docs, with `inScope` and `"reviewed": false`. Unmatched findings are triaged in `bench/<app>/triage.json`.
- CI job `bench` (ubuntu-24.04, Node 24) uploads `BENCHMARK.md` and is non-blocking.
- `scan --offline-safe` is an alias of `--offline`.

## 0.1.1 — 2026-10-15

### Phase 25 — 0.1.1 hardening (Windows + lazy SQLite)

- CI matrix is Linux, macOS, and Windows × Node 22 and 24.
- `node:sqlite` is loaded only when history/confirm open a database. `node --import fullshield/runtime/register -e "1"` prints nothing on stderr. Runtime entry points do not statically import sqlite.
- Dashboard `HistoryDb.close()` is idempotent and uses try/finally so Windows can unlink `history.db`.
- Fixer/agent diffs are `core.autocrlf`-independent: normalize to `\n` for compare, restore the file's original EOL on apply. Git pathspecs use POSIX slashes.
- `--import` child processes use `pathToFileURL(...).href` (`importHref`), never a bare absolute path.
- Flood test measures retained-heap delta after GC (< 10 MB) and asserts LRU sizes (512 / 64 / 128). Rate limiter covers the exact window edge and empty-then-refill.
- CI pins `ubuntu-24.04` and uses checkout/setup-node/upload-artifact v7 (Node 24 runtime).
- `@modelcontextprotocol/sdk` and `zod` are optional peerDependencies, lazy-imported only by `fullshield mcp`. Other scan/runtime deps stay required.
- `npm pack` ships `README.md` at the tarball root. `package.json` has no empty `readme` field (that left the npm packument as `"readme": ""`).

## 0.1.0 — 2026-10-14

First public alpha (Core 1–10, Pro 11–16, Frontier 17–24 behind flags, harden-1–6).

**Shipped (stable):** scan (deps + reachability, secrets, SAST, config), reports, baseline, fix, runtime guard, watch, edge, SBOM, CI gate.

**Experimental flags (off by default):**
- `scan --ai explain` and `fix --ai` only. Explain never shows a verdict. `--ai triage` and `--ai logic` are not a CLI surface. Live Ollama is `FULLSHIELD_AI_LIVE=1` (never CI).
- `FULLSHIELD_EXPERIMENTAL_RASP=1` — structure-change sink hooks (`--import fullshield/runtime/register` or `import 'fullshield/runtime/auto'`).
- `FULLSHIELD_EXPERIMENTAL_VPATCH=1` — `scan --emit-virtual-patches`.
- `FULLSHIELD_EXPERIMENTAL_HONEY=1` — `honey init`.
- `FULLSHIELD_EXPERIMENTAL_SUPPLY=1` — `fullshield install` (static only).
- `FULLSHIELD_EXPERIMENTAL_CONFIRM=1` — localhost / 127.0.0.1 / FullShield-started container only.
- `FULLSHIELD_EXPERIMENTAL_MCP=1` — read-only MCP (`propose_fix` returns diffs only).
- `FULLSHIELD_EXPERIMENTAL_LLM=1` — `LLM-001`–`LLM-005`.
- `FULLSHIELD_EXPERIMENTAL_PLATFORM=1` — threat-model, `--changed`/`--since`, workspaces, local dashboard.
- `FULLSHIELD_EXPERIMENTAL_COMPLIANCE=1` — `report --compliance` (not a certification or audit).
- `FULLSHIELD_EXPERIMENTAL_IAC=1` — light IaC rules.
- `FULLSHIELD_EXPERIMENTAL_AGENT=1` — remediation agent (localhost mock API + local git only).

**Publishing:** npm trusted publishing (OIDC) stages with `--provenance`; a maintainer approves with 2FA. No `NPM_TOKEN`.

### harden-5

- SSRF host normalization: IPv6 brackets, IPv4-mapped, decimal/octal/hex/short IPv4, trailing dots, resolve-at-connect, fetch redirect re-check.
- Attack corpus from PayloadsAllTheThings (vendored, attributed). Benign corpus ≥ 300. Per-category rates printed in verify.
- `RASP-SINKS.md` inventory. Async ALS tests (fs/promises, exec/spawn, sqlite, fetch, http). pg/mysql2 mocked query hooks.

### harden-6

- `DEPS-MALICIOUS-001` for OSV `MAL-` / malicious classification: always critical, never downgraded by reachability or dev-only.
- Honeytokens: decoy-route hits are low + aggregated; only canary credential use is critical. Threat auto-block is opt-in with a max duration (shared-IP / NAT risk). `honey init` writes fake values that secrets do not flag and appends them to `.gitignore`.
- Official MCP SDK stdio (`fullshield mcp --stdio`) plus SDK-client tests.

### Frontier (experimental)

- **Phase 24:** remediation agent (`FULLSHIELD_EXPERIMENTAL_AGENT=1`). Opens PRs via a localhost mock API against a local bare repo only. Never merges, never pushes to protected branches, stops on test failure.
- **Phase 23:** compliance mapping (OWASP/CWE/ASVS/PCI; every report says not a certification or audit) and light IaC (`FULLSHIELD_EXPERIMENTAL_COMPLIANCE=1` / `FULLSHIELD_EXPERIMENTAL_IAC=1`).
- **Phase 22:** threat-model, incremental `--changed`/`--since`, workspaces, local dashboard (`FULLSHIELD_EXPERIMENTAL_PLATFORM=1`). Dashboard binds 127.0.0.1 and validates Host.
- **Phase 21:** MCP server (`FULLSHIELD_EXPERIMENTAL_MCP=1`, read-only; `propose_fix` returns diffs only) and LLM-app rules `LLM-001`–`LLM-005` (`FULLSHIELD_EXPERIMENTAL_LLM=1`).
- **Phase 20:** exploit confirm (`FULLSHIELD_EXPERIMENTAL_CONFIRM=1`). Scope lock: localhost / 127.0.0.1 / FullShield-started container only (refuses public DNS names and IPv6). Harmless canaries for SQLi / CMDi / path / IDOR.
- **Phase 19:** supply-chain defense + `fullshield install` (`FULLSHIELD_EXPERIMENTAL_SUPPLY=1`). Static only (never executes packages). Seeded install-script + `.npmrc`/network heuristic, version-diff behavior change, cooldown, lockfile host, dependency confusion, provenance drop. Registry locked to `registry.npmjs.org`.
- **Phase 18:** virtual patches (`scan --emit-virtual-patches`, `FULLSHIELD_EXPERIMENTAL_VPATCH=1`), egress allowlist, `honey init` (`FULLSHIELD_EXPERIMENTAL_HONEY=1`), threat score log→challenge→block.
- **Phase 17 RASP:** structure-change sink hooks (`node:sqlite`, `child_process`, `fs`, `http(s)`/`fetch`, plus load-time wraps for `pg`/`mysql2`/…). Off unless `FULLSHIELD_EXPERIMENTAL_RASP=1`. Default `monitor`. Fail-open on hook errors. Activate with `--import fullshield/runtime/register` or `import 'fullshield/runtime/auto'`.

### harden-4

- Live Ollama path behind `FULLSHIELD_AI_LIVE=1`; `npm run test:live-ai` is never CI. Honest results in `benchmarks/AI-REPORT.md`.
- Yarn/pnpm lockfile edges; `reachability-unknown` keeps severity when edges are missing.
- LRU caps on the rate-limiter IP map and anomaly route/param maps.
- Mutation-smoke covers EDGE-*, AI-INJECT-001, DEPS-NOLOCK-001, and interproc taint.
- README: `--ai` experimental; AI-INJECT-001 is a three-phrase heuristic.

### Pro (11–16)

- `watch` alerts only on new OSV hits.
- `edge` GET/HEAD posture (CDN/WAF headers, HTTPS, security headers, exposure probes).
- AI provider layer (off by default). `AI-INJECT-001` phrase heuristic.
- Runtime anomaly baselines (no LLM).

### Core (1–10) and harden-1–3

- Secrets, deps (OSV + typosquat), SAST taint (intra + interproc depth 5), config.
- Reachability: reachable / imported-not-called (−1) / reachable-via-dependency (kept) / not-imported (−2). Dev-only overlay.
- Reports: console, JSON, SARIF 2.1.0, Markdown, HTML.
- `fix --apply` snapshot restore; helmet/secret-env are `safe: false`.
- Runtime Express + Fastify guards. `init` and `notify`.
