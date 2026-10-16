# FullShield — Build Spec for Cursor (full, rev 2026-10-15)

> Package: `fullshield` on npm (owner `kathan2404`). Repo: https://github.com/kathanp/fullshield (public, MIT).
> Language: TypeScript (strict). Runtime: Node.js ≥ 22.13. Distribution: one npm package (CLI + library + runtime middleware).
> Live on npm: `0.1.0`, `0.1.1` (both with provenance), `0.1.3` (**published WITHOUT provenance — must never happen again**). Placeholders `0.0.0-stage`, `0.0.1` deprecated. `0.1.2` was never published.
> Phases 1–35 are built and merged on `main` and `next`. This file is the single source of truth and replaces every earlier spec. It contains: hard rules (Section 0), verification (1), release protocol (2), benchmark protocol (3), full product/architecture/module design (4–24), phases 1–35 reference (25–27), and depth phases 36–45 (29).

---

## 0. HARD RULES (read first, apply always, no exceptions)

Breaking any rule below = stop work and report to the human. Do not "fix forward" around a rule.

### 0.1 Authority
- **R1.** The human approves: tags, publishes, merges to `main`, ground-truth reviews, test edits, threshold changes, and moving any feature from experimental to stable. Cursor never does these without an explicit "go" in the current message.
- **R2.** If a human instruction conflicts with this spec, ask before acting. If this spec conflicts with code comments or other docs, this spec wins.

### 0.2 Tests and evidence
- **R3.** Never modify, delete, skip, or weaken an existing test, fixture, `expected-findings.json`, `ground-truth.json`, or `triage.json` to make anything pass. If a test is wrong, stop and explain; the human decides.
- **R4.** Write the failing test first (red), then implement (green). Every rule has ≥ 1 positive and ≥ 1 negative fixture.
- **R5.** No stubs that pretend to work. A feature that can't meet its acceptance criteria ships behind its experimental flag or is left out.
- **R6.** Never invent vulnerability data. Dependency advisories come only from OSV (https://api.osv.dev) or `npm audit --json`. Never invent finding counts, benchmark numbers, or tool comparisons.
- **R7.** Cursor never grades its own work as final. Any number that appears in README, CHANGELOG, BENCHMARK.md, COMPARISON.md, or a release note is either from human-reviewed ground truth or labeled `unreviewed`.
- **R8.** Paste real command output. Never summarize a failing run as passing. For long output, paste the summary table plus every failure in full.
- **R8a. Fixture reclassification:** an attack fixture may move to the benign corpus only if (a) it provably cannot change the sink's structure in its context, AND (b) a genuine breakout payload for that same context is added to the attack corpus and is detected. Document both in the fixture file. Report to the human (counts as R3 decision).

### 0.3 Stable behavior
- **R9.** "Stable output" = default `fullshield scan --json` findings `(ruleId, file, line, severity)` on `test/fixtures/vulnerable-app`, `test/fixtures/clean-app`, and every app in `bench/`. `scripts/default-scan-diff.mjs` compares against the snapshot of the last published version.
- **R10.** Any stable-output change requires: (a) human approval before merge, (b) a CHANGELOG entry under **"New/changed stable findings — may change CI results; use --update-baseline"**, (c) a **minor** version bump (R16).
- **R11.** Every new feature ships behind `FULLSHIELD_EXPERIMENTAL_<NAME>=1` and/or `--experimental-<name>`, off by default. Promotion to stable follows Phase 43 only.
- **R12.** clean-app produces 0 findings of any severity in default scan, always.

### 0.4 Code and dependencies
- **R13.** No new hard runtime `dependencies`. New libraries go in optional `peerDependencies` (`peerDependenciesMeta.optional: true`), lazy-loaded with `import()` only by the command that needs them, with a clear "install X to use this feature" error.
- **R14.** Runtime entry points (`fullshield/runtime*`) import zero scanner code and never load `node:sqlite` at import time. `node --import fullshield/runtime/register -e "1"` prints nothing on stderr.
- **R15.** Never execute scanned code. Never install analyzed packages. Never send code to a network service without an explicit opt-in flag (`--ai`; `--verify-secrets` + `--i-own-these-credentials`). Never contact hosts other than OSV, registry.npmjs.org, user-configured webhooks/AI providers, or localhost.

### 0.5 Versioning
- **R16.** 0.x semver: **patch** = bug fixes only, no new features, no stable-output change. **minor** = any new feature (even experimental), new rule ID, new command/flag/export, or stable-output change. Enforced by `scripts/semver-check.mjs` (Phase 36).
- **R17.** Never reuse, decrease, or delete a version. Published versions are permanent. Fix forward only.

### 0.6 Workflow
- **R18.** All work on `next` (or `phase-N` worktrees off `next`). `main` only via PR from `next`, full CI matrix green, human approval.
- **R19.** Commit message per phase: `phase-N: <summary>`. Never mix phases in one commit.
- **R20.** Before every commit: `npm run verify` passes locally. Before every merge into `next`: `npm run verify` + `node scripts/default-scan-diff.mjs` (empty unless R10 approved).
- **R21.** Parallel subagents: one git worktree per phase on branch `phase-N`. Integrate into `next` sequentially in numeric order; full verify + diff after each merge. Shared files (CLI registration, rule registry, compliance map, CHANGELOG, README) are appended to, never rewritten.
- **R22.** Every platform-sensitive test (paths, filenames, shell, line endings) must pass on Linux, macOS, Windows, or use `it.skipIf(process.platform === 'win32')` with a comment giving the reason. No `"` in filenames, use `path.join`, never hardcode `/`. `--import` paths use `pathToFileURL(...).href`.

### 0.7 Stop conditions (stop immediately and report)
- S1. Stable-output diff not pre-approved.
- S2. Any existing test/fixture/ground-truth needs editing.
- S3. A phase can't meet acceptance criteria.
- S4. Same CI failure twice in a row.
- S5. Coverage within 2 points of any threshold.
- S6. A publish would lack provenance, or `npm pack` exceeds budget (Phase 36).
- S7. Any instruction would require breaking R1–R22.

### 0.8 Report format (every phase, every time)
```
Phase N — <name>
Branch/commit: <branch> <sha> | pushed: yes/no | merged into next: yes/no
Flag: FULLSHIELD_EXPERIMENTAL_<NAME> (or "stable — approved by human on <date>")
Built: <bullets>
Not done / limitations: <bullets>
Tests added: <n> | total: <n>
default-scan-diff: EMPTY | <diff>
verify:phase N: <summary table + any failures in full>
Benchmark impact: <per app, labeled tuning/seen/untouched, reviewed/unreviewed> or "none (experimental only)"
Next CI: <link> <status>
Needs human decision: <list or "none">
```

---

## 1. Verification Protocol

### 1.1 Required npm scripts (package.json)
```json
"scripts": {
  "build": "tsup",
  "typecheck": "tsc --noEmit",
  "lint": "eslint . --max-warnings 0",
  "test": "vitest run",
  "test:watch": "vitest",
  "test:coverage": "vitest run --coverage",
  "test:e2e": "vitest run test/e2e",
  "bench": "node scripts/bench.mjs",
  "bench:public": "node scripts/bench-public.mjs",
  "verify": "node scripts/verify.mjs",
  "verify:phase": "node scripts/verify.mjs --phase"
}
```

### 1.2 `scripts/verify.mjs` (in order, stop on first failure)
1. `typecheck` → `lint` → `build`.
2. `test:coverage` with thresholds in `vitest.config.ts`: **lines ≥ 80%, branches ≥ 80%** for `src/`; `src/modules/**` ≥ 85% lines; `src/fixer/**` ≥ 90% lines; every new source file ≥ 80% branches. Keep actual ≥ 2 points above every threshold (S5). Never raise a threshold to sit just under current coverage.
3. **Anti-cheat** (fail if any): `.only(`, `.skip(`, `it.todo(`, `xit(`, `xdescribe(` in `test/` (platform skips only per R22); a test file with zero `expect(`; source containing `TODO: implement`, `throw new Error('Not implemented')`, or a function returning a hardcoded fixture result.
4. **E2E against the built binary** (`node dist/cli/index.js`):
   - `scan test/fixtures/vulnerable-app --json` → every ID in `expected-findings.json` present.
   - `scan test/fixtures/clean-app --fail-on high` → exit 0.
   - `scan test/fixtures/vulnerable-app --fail-on high` → exit 1.
   - `scan ... --sarif out.sarif` → validates against SARIF 2.1.0 schema.
   - No unmasked fake secret in any output format.
5. **Mutation smoke** (`scripts/mutation-smoke.mjs`): disable each SAST/secrets rule's detection function (and the extra targets list) → its tests must fail. If they still pass, the tests are fake → fail.
6. **default-scan-diff** (Phase 36) — empty, or exactly matches the approved diff file.
7. Summary table: phase, tests, coverage lines/branches, implemented modules, expected vs found, vulnerable-app finding count, clean-app high/critical, attack/benign corpus results. Then phase acceptance criteria.

`verify:phase N` = steps 1–7 plus that phase's acceptance criteria.

### 1.3 CI (`.github/workflows/ci.yml`)
- Push to `next`: one job `verify (ubuntu-24.04, node 24)`.
- PR to `main` and push to `main`: full matrix `ubuntu-24.04`, `macos-latest`, `windows-latest` × Node 22, 24.
- Uploads coverage and SARIF artifacts. Non-blocking `bench` job uploads BENCHMARK.md.
- Actions pinned by commit SHA (Phase 45). Never `ubuntu-latest` for jobs.
- `main` branch protection requires the 6 matrix jobs by exact name. When job names change, update required checks in the same PR, after the new jobs have reported once.

### 1.4 Publish (`.github/workflows/publish.yml`)
- Trigger: tags `v*` only. Node 24. `npm install -g npm@latest` (trusted publishing needs npm ≥ 11.5.1).
- `permissions: id-token: write, contents: read`. No `NPM_TOKEN`. No GitHub Environment. Trusted publishing (OIDC) configured on npmjs.com for `kathanp/fullshield`, workflow `publish.yml`.
- Steps: `npm ci` → `npm run verify` → `node scripts/semver-check.mjs` → `node scripts/pack-budget.mjs` → `npm publish --provenance --access public` → **post-publish gate**: poll `npm view fullshield@$VERSION dist.attestations` (up to 10 min; staged approval may delay) and fail loudly if empty.
- Staged publish approval on npmjs.com stays ON (human 2FA approves every publish).
- Never edit the staged manifest or inject README text into it (Cloudflare blocks it; npm/cli#9405 tracks the empty packument README).

---

## 2. Release Protocol (human-gated)

1. Target phases merged into `next`; `next` CI green.
2. `node scripts/default-scan-diff.mjs --against <last published version>` → attach output.
3. `node scripts/semver-check.mjs` → required bump. Human confirms version.
4. Bump version + CHANGELOG on `next` **before** CI, so the tagged commit is the tested commit.
5. Untouched-holdout run (Section 3) → recall for release notes, labeled reviewed/unreviewed.
6. `npm pack --dry-run` within budget.
7. PR `next` → `main`. Full matrix green. Human approves merge.
8. Human says "go" → tag `vX.Y.Z` on the merged `main` commit (same SHA CI tested).
9. Human approves the staged publish on npmjs.com.
10. Post-publish gate passes (provenance present). Stranger check: fresh temp dir, empty npm cache (`npm_config_cache=$(mktemp -d)`), `npx fullshield@X.Y.Z --version`, then on a cloned NodeGoat with a `fullshield.config.json`: `scan`, `scan --json`, `scan --sarif out.sarif`, `scan --fail-on high`, `fix`, `init` (in a copy), `sbom --format cyclonedx`. Any "Cannot find module" or crash = release bug → fix forward with a patch.
11. Update Section 30 status table.
12. Dependabot PRs are not merged during steps 1–10.

---

## 3. Benchmark Protocol (anti-overfitting)

- **B1. Holdout registry** `bench/holdouts.json`: every benchmark app `{name, repo, sha, status: "tuning" | "seen" | "untouched", reviewed: bool, firstRunDate}`.
- **B2. Tuning apps** (current: NodeGoat, Juice Shop, DVNA, snyk-labs/nodejs-goof, cr0hn/vulnerable-node): rules may be fixed from their misses. Their recall is labeled `seen`, never a headline.
- **B3. Untouched apps:** scanned exactly once per release, after code freeze. No rule change may cite an untouched app's result. After a release uses it, it becomes `seen`. Keep ≥ 2 untouched apps in reserve at all times.
- **B4. Ground truth:** built only from each app's own published vulnerability docs; every entry cites its source; `"reviewed": false` until the human flips it. Each entry has `inScope` (class FullShield claims to detect statically: sqli, nosqli, cmdi, path, xss, ssrf, redirect, eval, jwt, crypto, proto, secrets, deps, config) or is out-of-scope with a one-line reason. Recall is computed on in-scope entries only.
- **B5. Matching:** same class + same file + line ±3. Moving the reported line of an existing finding is never a recall gain.
- **B6. Precision:** every unmatched finding triaged `realIssue | falsePositive | unsure` with a reason. Precision is labeled `self-triaged` until the human samples ≥ 20 findings per app and confirms.
- **B7. Headlines:** only untouched-app recall from reviewed ground truth may appear in README or release notes. All else stays in BENCHMARK.md with labels.
- **B8. Never** copy benchmark-app code into fixtures. Fixtures reproducing a pattern are written from scratch.

---

## 4. Product Scope

### 4.1 Goals
A single tool covering the full cycle for Node.js/TypeScript backends:

**Detect → Classify → Report → Notify → Fix (suggest/patch) → Prevent (CI gate + runtime monitor)**

### 4.2 What it detects (stable core)
| Module | Detects | Source of truth |
|---|---|---|
| `deps` | Known-vulnerable npm packages (direct + transitive), malicious packages (OSV `MAL-`), deprecated packages, typosquat-suspicious names, missing lockfile | OSV API, lockfile parsing |
| `secrets` | Hardcoded API keys, tokens, private keys, DB URLs with passwords, committed `.env` files, hardcoded session secrets | Regex + entropy rules |
| `sast` | SQL/NoSQL/command injection, path traversal, `eval`/`new Function`/`vm`, SSRF, open redirect, JWT misuse, weak crypto, prototype pollution, XSS, missing auth middleware (low confidence) | AST taint (intra-function + cross-file, depth 5) |
| `config` | Missing helmet, permissive CORS, no rate limit on auth routes, unbounded body parser, `err.stack` leaks, directory listing, insecure Dockerfile, install scripts | File + AST checks |
| `runtime` | Request monitoring (signature stopgap), auth-route rate limiting, body size/depth limits; experimental RASP sink hooks | In-process middleware |

### 4.3 Non-goals (README must state these)
- Does NOT find business-logic/authorization bugs (IDOR, broken access control) deterministically. Routes without auth middleware are flagged *suspicious*, nothing more.
- Does NOT replace a penetration test.
- Does NOT auto-delete code, auto-merge, or auto-deploy, ever.
- Does NOT stop OS-level or network-service exploits (e.g. OpenSSH regreSSHion, kernel bugs). `host` only reports exposure.
- Is NOT a WAF, firewall, DDoS mitigation, or host intrusion prevention system. Use a CDN/WAF, fail2ban, or CrowdSec.
- Does NOT scan container images or OS packages. Use Trivy or Grype.
- Does NOT run attacks against any host other than localhost or a container FullShield started.
- Does NOT detect cyber-physical or hardware attacks (ICS/SCADA sabotage, hardware implants, firmware). The closest in-scope analog is npm supply-chain heuristics — software only.
- JS/TS only.

### 4.4 Positioning (honest; applies to README and all copy)
Every layer exists elsewhere: Snyk, Socket, Semgrep, OSV-Scanner (deps/reachability); Semgrep, Snyk Code, CodeQL (SAST); Gitleaks, TruffleHog (secrets); Aikido Zen, Datadog, Contrast (runtime). FullShield's niche: one MIT `npx` command, no account, deps-reachability + SAST + secrets + config + runtime monitor, with published benchmarks including misses. Differentiation comes from **measured detection quality**, not feature count. Never use "one of a kind", "complete protection", "full shield from cyber attacks", or "prevents attacks". Say "public alpha", "0.x".

---

## 5. Usage (target UX)

```bash
npx fullshield scan                     # human-readable output
npx fullshield scan --json              # machine output
npx fullshield scan --sarif out.sarif   # GitHub Code Scanning
npx fullshield scan --fail-on high      # exit 1 if any finding >= high (CI gate)
npx fullshield scan --update-baseline   # accept current findings; CI fails only on new ones
npx fullshield fix                      # proposed patches (dry run)
npx fullshield fix --apply              # apply safe fixes (clean git tree required)
npx fullshield init                     # config + CI workflow + pre-commit hook
npx fullshield notify --slack $WEBHOOK  # summary of last scan
npx fullshield watch                    # alert only on new OSV advisories
npx fullshield edge https://example.com # posture check of a URL you own
npx fullshield sbom --format cyclonedx  # CycloneDX 1.5
```

Library:
```ts
import { scan } from 'fullshield';
const result = await scan({ cwd: process.cwd(), modules: ['deps', 'secrets', 'sast', 'config'] });
```

Runtime guard:
```ts
import express from 'express';
import { shieldGuard } from 'fullshield/runtime/express';
const app = express();
app.use(shieldGuard({ mode: 'monitor', onEvent: (evt) => console.warn(evt), authRoutes: ['/login'] }));
```
Modes: `monitor` (log only, default, recommended in production) | `block` (403 + log).

---

## 6. Architecture

```
fullshield/
├── src/
│   ├── cli/                 # commander entry; command registration
│   ├── core/                # engine (orchestrate, merge, dedup), finding, config, fileWalker, baseline
│   ├── modules/
│   │   ├── deps/            # lockfile parsers (npm v2/v3, yarn classic, pnpm) + edges, OSV client, cache, reachability
│   │   ├── secrets/         # rules, entropy, masking, staged/history/bundle
│   │   ├── sast/            # parser (@typescript-eslint/typescript-estree, lazy), rule runner, interproc taint, rules/
│   │   ├── config/          # helmet, cors, rate-limit, body limit, dockerfile, npm scripts, trust proxy
│   │   ├── edge/ supply/ mcpcfg/ host/ iac/ compliance/ ...
│   ├── fixer/               # patch generation, git safety, snapshot restore
│   ├── reporters/           # console, json, sarif, markdown, html, pr-summary
│   ├── notifiers/           # slack, generic webhook, smtp
│   ├── runtime/             # express, fastify, koa, hono, rasp/, register, auto, dlp, anomaly
│   └── ai/                  # providers, redaction, parse, injection
├── rules/                   # one .md per rule ID (id, title, severity, CWE, OWASP, fix)
├── bench/                   # harness, <app>/ground-truth.json, triage.json, holdouts.json, snapshots/
├── test/
│   ├── fixtures/vulnerable-app/   # intentionally vulnerable Express app
│   ├── fixtures/clean-app/        # must produce zero findings
│   ├── unit/ e2e/
├── templates/               # GitHub Action, GitLab CI, pre-commit hook, watch workflow
└── scripts/                 # verify, mutation-smoke, bench, bench-public, default-scan-diff, semver-check, pack-budget
```

### 6.1 Core data model
```ts
type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

interface Finding {
  id: string;              // stable hash of ruleId + file + normalized snippet
  ruleId: string;          // e.g. "SAST-SQLI-001"
  module: string;          // 'deps' | 'secrets' | 'sast' | 'config' | 'edge' | 'supply' | 'mcp' | 'host' | ...
  title: string;
  severity: Severity;
  confidence: 'low' | 'medium' | 'high';
  cwe?: string;
  file?: string; line?: number; column?: number;
  snippet?: string;        // secrets MUST be masked: first 4 chars + ****
  message: string;         // what's wrong, plain English
  remediation: string;     // how to fix
  fix?: FixProposal;
  references?: string[];   // OSV id, CVE, docs
  trace?: Array<{ file: string; line: number; note: string }>;  // SARIF codeFlows
  reachability?: 'reachable' | 'imported-not-called' | 'reachable-via-dependency' | 'not-imported' | 'reachability-unknown' | 'symbol-reachable' | 'symbol-not-called';
  source?: 'rule' | 'ai';
  status?: 'confirmed' | 'unconfirmed';
}

interface FixProposal {
  kind: 'dependency-bump' | 'dependency-override' | 'code-patch' | 'config-add';
  safe: boolean;           // only safe fixes apply without --unsafe
  diff: string;            // unified diff
}
```

### 6.2 SAST rule interface
```ts
interface SastRule {
  meta: { id: string; title: string; severity: Severity; cwe: string; docs: string };
  create(ctx: RuleContext): Partial<Record<AstNodeType, (node: any) => void>>;
}
```
Taint: sources `req.body/query/params/headers/cookies`, destructured request params, `process.argv` (+ framework sources behind flags). Propagation: assignment, concat, template literals, method-call receivers, function params and returns (same file and cross-file via `require`/`import`, depth 5). Sanitizers are sink-specific: parameterized query APIs (SQL), zod/joi/yup `.parse` result only, `path.resolve` + `startsWith(base)` (path), `encodeURIComponent` (URL/redirect only), HTML escape/DOMPurify (XSS only). `JSON.parse`/generic `parse` never clear taint. Parameterized queries are never flagged.

---

## 7. Module Details

### 7.1 deps
- Parse `package-lock.json` (v2/v3 + dependencies-tree fallback), `pnpm-lock.yaml`, `yarn.lock` (classic) → packages and dependency edges. Unknown/edge-less formats → `edgesKnown: false` → `reachability-unknown` (never a silent downgrade).
- OSV `/v1/querybatch` (ecosystem npm) then per-ID details. Cache `~/.cache/fullshield/osv/`, 24h TTL. `--offline` = cache only; never invents advisories.
- `DEPS-NOLOCK-001` (info) when manifest has no lockfile; exact pins still queried.
- `DEPS-MALICIOUS-001`: OSV `MAL-` or malicious classification → always critical, never downgraded. Remediation: remove package, delete node_modules, reinstall, rotate credentials.
- Reachability (stable): `reachable` (imported + called; kept), `imported-not-called` (−1), `reachable-via-dependency` (lockfile path from a production-imported direct dep; kept; path shown e.g. `express > body-parser > qs`), `not-imported` (−2, only when edges known), `reachability-unknown` (kept). Dev-only vulns → info `dev-only` unless production code imports the package. Test-file imports are not roots.
- Direct dep findings attributed to the `package.json` line.
- Fix: minimum non-vulnerable version from OSV ranges; bump safe if same major, unsafe otherwise. Transitive with no parent fix → `dependency-override` (unsafe) written to `package.json` `overrides` / `pnpm.overrides` / `resolutions`; never edits the lockfile; prints "run npm install".
- Typosquat: Levenshtein ≤ 1 vs a static popular list, direct deps only, min length 4, name not in top-packages list → medium, low confidence.

### 7.2 secrets
- Rules: AWS, Stripe, GitHub, Slack, Google, OpenAI/Anthropic-style keys, PEM private keys, DB URLs with inline passwords (placeholders like `<password>` skipped), hardcoded JWT secrets, generic high-entropy assignment (entropy > 4.5, length ≥ 20, key/secret/token/password names; low confidence), committed `.env*` (except `.env.example`, `.env.backup` honey decoy), `SECRET-SESSION-001` hardcoded express-session secret.
- String-literal concatenation folded before matching. Masking (`first4 + ****`) before any Finding exists; raw secrets never leave the module (tested in every output format).
- Remediation always: rotate the key; removing it from code is not enough because it stays in git history.
- `--staged` scans only the git index (pre-commit).

### 7.3 sast — stable rule set
| ID | Rule | CWE |
|---|---|---|
| SAST-SQLI-001 | Tainted input concatenated into SQL passed to query/execute | CWE-89 |
| SAST-NOSQLI-001 | Request input used directly as a Mongo filter value or `$where` on a Mongo/mongoose receiver, unless coerced (`String()`/`Number()`/`Boolean()`), schema-validated, or mongo-sanitize applied. Never on Sequelize/Prisma/TypeORM/Knex/Drizzle/unknown receivers | CWE-943 |
| SAST-CMDI-001 | Tainted input reaching `exec`/`execSync`/`spawn` with shell | CWE-78 |
| SAST-PATH-001 | Tainted input in `fs.*` path, `res.sendFile`, or archive extraction (zip-slip) without resolve + prefix check | CWE-22 |
| SAST-EVAL-001 | `eval`, `new Function`, `vm.run*`, library `eval` wrappers with non-literal | CWE-95 |
| SAST-SSRF-001 | Tainted URL into fetch/axios/http(s)/needle/got/request/superagent/undici | CWE-918 |
| SAST-REDIRECT-001 | Tainted value into `res.redirect` | CWE-601 |
| SAST-JWT-001 | `jwt.decode` for auth, `algorithms` includes `none`, or verify without allow-list | CWE-347 |
| SAST-CRYPTO-001 | md5/sha1 for passwords or `md5(tainted)` tokens; `Math.random` for tokens/ids | CWE-327/338 |
| SAST-PROTO-001 | Recursive merge/assign of tainted object without `__proto__` guard | CWE-1321 |
| SAST-XSS-001 | Tainted input into HTML `res.send`; `<%-`/`{{{` in templates; `autoescape: false` | CWE-79 |
| SAST-AUTH-001 | Data-touching route with no auth middleware in chain (low severity, low confidence) | CWE-862 |

### 7.4 config
- Express app factory and no helmet → medium (line-attributed to `express()` or commented-out helmet).
- `cors({ origin: '*', credentials: true })` or reflective origin → high.
- Auth routes without a rate limiter → medium.
- `express.json()` without limit → low.
- Error handler sending `err.stack` → medium.
- `serveIndex()` → `CONFIG-DIRLIST-001`.
- Dockerfile: no USER / root, `FROM *:latest`, `ENV *_KEY=`/`*_SECRET=` → medium/high.
- Lockfile `hasInstallScript` → info.

### 7.5 runtime (stable middleware + experimental RASP)
- Request context via `AsyncLocalStorage`.
- Signature-based inspector (SQLi/XSS/path) — a stopgap, not a WAF; `monitor` default.
- Sliding-window rate limiter for `authRoutes` (pluggable store), LRU caps (keys 10k, routes 1k, params 200, configurable).
- Body size/depth/key limits.
- Events never include raw bodies: rule id, path, IP, truncated masked sample.
- Budget: < 1 ms p95 added latency on a typical JSON request (benchmark).
- Runtime bundle tiny, no scanner imports (R14).

---

## 8. Fix Engine
- `fix` = dry run, unified diffs.
- `fix --apply`: refuse dirty git tree unless `--force` (which skips files with uncommitted changes); create branch `fullshield/fixes-<timestamp>` unless `--no-branch`; apply `safe: true` only unless `--unsafe`; snapshot each file's bytes before writing; run project tests if present; restore snapshots on failure (never `git checkout --`). Restores original line endings.
- Safe: same-major bumps, JSON body limit, `Math.random` → `crypto.randomUUID()`/`randomBytes`, `.env` in `.gitignore`.
- Unsafe (shown in dry run, `--unsafe` to apply): `helmet()` insertion, secret → `process.env.X` with rotate comment, major bumps, dependency overrides, code patches.
- Never removes code blocks. Never deletes user files. Never edits lockfiles by hand.

---

## 9. Prevention (CI + hooks)
`fullshield init` generates:
- `.github/workflows/fullshield.yml`: `scan --sarif` on PRs, SARIF upload, `--fail-on high`.
- `.gitlab-ci.yml` snippet: same, JSON artifact.
- `.github/workflows/fullshield-watch.yml`: daily `watch`.
- `.fullshield/pre-commit.sh` (plain shell): `scan --modules secrets --staged`.
- `fullshield.config.json`:
```json
{
  "modules": ["deps", "secrets", "sast", "config"],
  "failOn": "high",
  "ignore": ["dist/**", "**/*.test.ts"],
  "baseline": ".fullshield-baseline.json",
  "notify": { "slackWebhookEnv": "FULLSHIELD_SLACK_WEBHOOK" }
}
```
- Baseline (`--update-baseline`): CI fails only on new findings.
- Inline suppression: `// fullshield-ignore SAST-SQLI-001: reason` (reason required; missing reason does not suppress).
- `--verify-secrets` is never placed in generated CI templates.

---

## 10. Reporting & Notification
- Console: grouped by severity, file:line, one-line fix each.
- JSON: `Finding[]` + summary counts + metadata (version, duration, modules).
- SARIF 2.1.0, schema-validated; `codeFlows` from traces.
- Markdown / HTML (escaped, secrets masked).
- `--pr-summary` (experimental): deterministic Markdown of new findings vs baseline; text only, never posts.
- Notifiers: Slack webhook, generic webhook, SMTP; creds from env only; summaries and masked data only. Last scan stored in `.fullshield/last-scan.json` (always ignored by the walker).

---

## 11. Security of the Package Itself (non-negotiable)
- No install/postinstall scripts.
- Hard runtime deps ≤ 6 (currently: commander, ignore, picocolors, @typescript-eslint/typescript-estree). Optional peers: express, fastify, koa, hono, zod, @modelcontextprotocol/sdk. Lockfile committed.
- Publish only from CI via trusted publishing with `--provenance`; post-publish attestation gate (S6). No long-lived npm tokens. 2FA on npm and GitHub. Staged approval on.
- Tarball: `dist/` (no `.map`), README, LICENSE, CHANGELOG, templates, rules. Budget: unpacked ≤ 2.0 MB, ≤ 120 files (Phase 36).
- Scanned code is never executed. Parse only.
- Network: OSV, registry.npmjs.org (supply-chain features), user-configured webhooks/AI providers, localhost (confirm/agent/dashboard). `--offline` available.
- Dogfood: FullShield scans its own repo in CI.
- No telemetry.

---

## 12. Phased Build Plan — Core (1–10) and Pro (11–16) [DONE]

| Phase | Build | Acceptance criteria |
|---|---|---|
| 1 | Scaffold: TS strict, ESLint, Vitest, tsup, commander CLI, Finding model, config loader, file walker, console + JSON reporters | `scan` runs on fixtures with 0 modules, exit 0 |
| 2 | `secrets` + masking + `--staged` | All seeded secrets found; 0 FP in clean-app; never printed unmasked |
| 3 | `deps`: lockfile parsers, OSV batch, cache, offline | Seeded `lodash`/`minimist` found; OSV mocked |
| 4 | SAST engine + SQLI, CMDI, PATH, EVAL, JWT, CRYPTO | Positive + negative per rule; parameterized not flagged |
| 5 | Remaining SAST rules + `config` | All rules tested; clean-app 0 high/critical |
| 6 | SARIF/MD/HTML, `--fail-on`, baseline, suppression | SARIF validates; baseline suppresses old, new fail |
| 7 | Fix engine | Safe fixes on a copy; revert on test failure |
| 8 | Runtime middleware Express/Fastify, rate limiter, bench | Blocks payload suite in block mode; p95 < 1 ms |
| 9 | `init`, notifiers | Valid YAML; webhook tested against local mock |
| 10 | README, rule docs, CHANGELOG, publish config | `npm pack` reviewed; README states non-goals |
| 11 | `watch` (new OSV only) | Second unchanged run sends no alert |
| 12 | `edge` posture | Mock server tests per check; GET/HEAD only |
| 13 | Cross-file taint, reachability, SBOM | 3-file trace; unreachable downgraded; CycloneDX validates |
| 14 | AI provider layer (BYO key), redaction, cost cap | No secrets outbound; `--ai` off = zero AI calls |
| 15 | AI explain + verified fix | Fixes pass rescan + tests or are discarded |
| 16 | AI logic hunter + anomaly baseline | `source: ai`, confidence ≤ medium, never fails CI |

Hardening passes harden-1…harden-6 and release-prep are recorded in PROGRESS.md.

---

## 13. Test Fixtures
- `test/fixtures/vulnerable-app/`: at least one instance of every stable rule, e.g.:
```ts
app.get('/user', (req, res) => db.query("SELECT * FROM users WHERE id = " + req.query.id)); // SQLI
app.get('/file', (req, res) => res.sendFile(req.query.name));                                // PATH
app.post('/run', (req, res) => exec(`ping ${req.body.host}`));                                // CMDI
const token = Math.random().toString(36);                                                    // CRYPTO
const AWS_KEY = "AKIA" + "XXXX…";                                                            // SECRETS (fake, concatenated)
```
- `clean-app/`: same features written safely; 0 findings (R12).
- Fake secrets are always concatenated or generated at test time; never realistic-looking committed keys (push protection).
- RASP corpora: attack payloads (vendored PayloadsAllTheThings, MIT attribution) + benign corpus (O'Brien, "SELECT your seat", dotted paths, URLs in comments). Each attack fixture records its sink context. Target ≥ 95% blocked, 0 benign blocked.
- Platform rules per R22.

---

## 14. Definition of Done (v1.0)
- Core stable with tests green; every experimental feature either promoted via Phase 43 or still flagged.
- Linux, macOS, Windows supported.
- 50k-LOC scan ≤ 60 s cold (excluding network) — Phase 42.
- clean-app 0 findings.
- Recall on ≥ 2 untouched apps with **reviewed** ground truth published (B7).
- Per-rule precision within Phase 41 budget.
- README lists non-goals and Known Limitations (Section 28).
- Every published version has provenance; dogfood passes in CI.

---

## 15. Post-launch Maintenance
- Weekly rule review; OSV is live, SAST rules need upkeep.
- Every user false-positive report → benign fixture + regression test.
- Every missed-attack report → attack fixture + regression test.
- Issue templates: bug, false positive, missed attack, new rule.

---

## 16. All-in-One Packaging
- One install: `npm i -D fullshield` / `npx fullshield`. Never split into separate packages.
- Subpath exports:
```json
"exports": {
  ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js" },
  "./cli": "./dist/cli/index.js",
  "./runtime": "./dist/runtime/index.js",
  "./runtime/express": "./dist/runtime/express.js",
  "./runtime/fastify": "./dist/runtime/fastify.js",
  "./runtime/koa": "./dist/runtime/koa.js",
  "./runtime/hono": "./dist/runtime/hono.js",
  "./runtime/rasp": "./dist/runtime/rasp.js",
  "./runtime/register": "./dist/runtime/register.js",
  "./runtime/auto": "./dist/runtime/auto.js",
  "./package.json": "./package.json"
},
"bin": { "fullshield": "./dist/cli/index.js" }
```
- Runtime path tiny (R14); test bundles runtime and asserts size budget and no parser imports.
- Heavy modules (SAST parser, YAML, SQLite, MCP SDK, zod) loaded with `import()` only when used.
- One version, one CHANGELOG.

Coverage map (README, honest):
| Layer | Covered by |
|---|---|
| Code vulnerabilities | `sast` |
| Dependencies (now + new CVEs later) | `deps` + `watch` |
| Secrets | `secrets` + pre-commit hook |
| App/server config | `config` |
| Live app-layer signals | `runtime` monitor; experimental RASP |
| AI editor / MCP configuration | `mcpcfg` (experimental) |
| Edge/DDoS layer | `edge` checks a CDN/WAF exists; mitigation is the CDN's job |
| Host / OS services | `host` reports exposure only (experimental); patching/blocking is the OS's and fail2ban/CrowdSec's job |

### 16.1 `edge`
```bash
npx fullshield edge https://example.com
```
- CDN/WAF detection by headers (`cf-ray`, `server: cloudflare`, `x-amz-cf-id`, `x-served-by`, …); none → high.
- TLS validity, expiry < 21 days → warn, HTTP → HTTPS redirect.
- Headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy.
- Probes (GET/HEAD only, ≤ 15 requests, 1 req/s): `/.env`, `/.git/HEAD`, `/package.json`, `/debug`, `/server-status`.
- Only user-passed URLs. No crawling, port scanning, or payload fuzzing. README: only scan sites you own or are authorized to test.

---

## 17. Advanced Engine (non-AI)

### 17.1 Cross-file taint
- Module graph from relative `require`/`import`, `require(x).Export`, `new Ctor()` methods, `this.method = fn`; TS path aliases and barrels in Phase 39/40.
- One finding per source→sink with full `trace`; SARIF `codeFlows`.
- Depth 5; per-file cache keyed by content hash.

### 17.2 Dependency reachability
- See 7.1. Phase 39 adds symbol-level reachability where advisory data names affected functions; never guesses symbols.
- Headline feature in README: turns hundreds of lockfile alerts into the ones that matter.

### 17.3 SBOM
- `fullshield sbom --format cyclonedx` → CycloneDX 1.5 with vuln references. Licenses only when present in data; never invented.

---

## 18. AI Layer (opt-in, never the source of truth)

### 18.1 Principles (enforced in code + tests)
1. Off by default. `--ai` off = zero AI network calls (test asserts).
2. BYO model: Anthropic, OpenAI, Ollama (local). Keys from env only (`FULLSHIELD_AI_PROVIDER`, `FULLSHIELD_AI_KEY`, `FULLSHIELD_AI_MODEL`).
3. Deterministic rules decide CI. AI never fails a build alone, never removes a deterministic finding.
4. Minimal redacted context: trace snippets ± 15 lines; secrets module redacts every outbound payload to `<REDACTED>`; test intercepts HTTP.
5. Scanned code is hostile input (prompt injection).
6. Bounded cost: `ai.maxCostUsd` (default $1), `ai.maxFindings` (default 50); cache by hash(prompt + model).
7. Structured JSON only, zod-validated; invalid → retry once → drop.

### 18.2 Prompt-injection hardening
- Code wrapped in delimited blocks; system prompt marks it untrusted.
- `AI-INJECT-001` (medium): comments containing phrases aimed at AI reviewers ("ignore previous", "mark as safe", "AI reviewer") — basic heuristic.
- Model never gets acting tools; deterministic code performs all actions.

### 18.3 AI features (all experimental)
| Mode | Status | Guardrail |
|---|---|---|
| `scan --ai explain` | experimental, user-facing | Explanation text only; never shows a verdict |
| `fix --ai` | experimental, user-facing | Verify loop: temp copy → rescan (finding gone, no new) → tests → keep only if all pass; max 2 attempts; reviewable diff; never writes user tree |
| `--ai triage`, `--ai logic` | internal only (`FULLSHIELD_AI_INTERNAL=1`); rejected by CLI | Live smoke results not good enough to advertise (see benchmarks/AI-REPORT.md) |

### 18.4 Runtime anomaly detection (statistical, no LLM)
- `shieldGuard({ anomaly: { learnMinutes } })`: per-route baselines; flags 401 spikes, new param names, 404 bursts. LRU-capped.

### 18.5 AI tests
- Recorded (VCR-style) fixtures in CI; `npm run test:live-ai` is opt-in, not in verify/CI.

---

## 19. Frontier: Runtime Self-Protection (RASP) [experimental]

### 19.1 Sink hooking
- CommonJS via `Module._load` hooks; ESM via `module.register()` loader hooks; `diagnostics_channel` where available.
- Hooked sinks: `pg`, `mysql2`, `better-sqlite3`, `node:sqlite` (only if the app imports it), `mongodb`, `mongoose`, ORM raw APIs (Phase 27), `child_process.*`, `fs.*`/`fs/promises`, `http(s).request`, `fetch` (undici), `axios`, `vm`, `res.redirect`, template render calls.
- Activation: `node --import fullshield/runtime/register app.js` or `import 'fullshield/runtime/auto'` first. Docs use the package specifier or `file://` URLs.
- Fail-open: hook errors emit `RASP-FAIL-OPEN-001` and call the original.

### 19.2 Structure-change detection
For each sink call, collect request input strings (query, body, params, headers, cookies, flattened). For each input appearing in the sink argument:
- **SQL:** dialect-aware tokenizer; input spanning more than one literal token (keywords, operators, comments, quotes) → injection. Numeric positions: anything beyond a single numeric token → injection.
- **Shell:** POSIX tokenizer; input introducing `;`, `|`, `&&`, `$()`, backticks, redirection, or new arguments → injection.
- **Path:** resolved path escapes the joined base, or null bytes → block.
- **NoSQL:** object with `$` operators where a scalar was expected → block.
- **SSRF:** resolve at connect time; block private/loopback/link-local/metadata (incl. IPv6 brackets, `::ffff:` mapped, decimal/octal/hex/short IPv4, trailing dots) when host came from input; re-check redirects; pin resolved IP.
- **Prototype pollution:** block `__proto__`, `constructor`, `prototype` keys; optional `Object.freeze(Object.prototype)` mode.

### 19.3 Virtual patching
- `scan --emit-virtual-patches` → `.fullshield/vpatches.json` `{ruleId, file, line, sink, route}`; runtime blocks only those route/sink pairs; reverts when findings disappear.

### 19.4 Egress control
- `egress.allow` exact hosts and `*.suffix` (subdomain-only; apex and suffix confusion denied) plus IP literals.

### 19.5 Honeytokens
- `honey init`: decoy `.env.backup` with obviously-fake canaries (`FULLSHIELD-HONEY-CANARY-NOT-A-CLOUD-KEY`, `fullshield-honey-db-canary://local`), decoy routes (`/admin.php`, `/.git/config`, `/wp-login.php`), entries added to `.gitignore`.
- Decoy-route hits: low severity, counted per IP per window; never 403 on route hits alone. Canary credential use: critical.

### 19.6 Attack response
- Threat score per IP/user; log → challenge (429) → temporary block → alert. Auto-block off unless `threatAutoBlock: true`; `threatMaxBlockMs` default 15 min. Shared-IP/NAT risk documented.

---

## 20. Frontier: Supply-Chain Defense [experimental]
- Static only; never executes or installs analyzed packages. Registry host locked to `registry.npmjs.org`.
- Malicious heuristics: install scripts, obfuscation, reads of `~/.npmrc`/`~/.ssh`/env combined with network calls (`SUPPLY-NPMRC-NET-001`), install scripts (`SUPPLY-INSTALLSCRIPT-001`).
- Version diffing → `SUPPLY-BEHAVIOR-001` on newly added scripts/network/child_process.
- Release cooldown (`deps.minReleaseAgeHours: 72`), provenance-drop detection, dependency confusion, maintainer change, lockfile non-registry URLs / altered integrity.
- `fullshield install <pkg>` wraps `npm install --ignore-scripts` + checks.
- Phase 31: `SUPPLY-WORM-001` (token read + publish/registry PUT/GitHub repo or workflow creation), `SUPPLY-WORKFLOW-001` (writes to `.github/`, `.git/hooks/`, CI config), provenance coverage score (unknown ≠ present), VEX output.

---

## 21. Frontier: Exploit Confirmation & Fuzzing [experimental, local only]
- Scope lock: `localhost`, `127.0.0.1`, or a container FullShield started. Refuses public names, IPv6, encoded IPv4 forms, metadata, `127.0.0.2`; raw authority checked.
- Route inventory from Express/Fastify (and Next/Nest/Hono/Koa behind flag) and OpenAPI.
- Harmless canaries only (marker `UNION SELECT`, `echo` token, planted canary file). Destructive payloads (`DROP`, `rm`, `dd`) rejected.
- Runtime-assisted confirmation via sink hooks in monitor mode. Property-based fuzzing (fast-check). IDOR confirmation with two configured test users.
- Findings get `status` and a reproducible `curl` proof against localhost.

---

## 22. Frontier: Platform & Intelligence [experimental]

### 22.1 MCP server
- `fullshield mcp --stdio` (official `@modelcontextprotocol/sdk`, optional peer). Tools: `scan`, `get_findings`, `explain_finding`, `propose_fix` (diff, `wrote: false`), `verify_fix` (temp copy). Read-only.

### 22.2 LLM-app security
- `LLM-001` input concatenated into system prompts; `LLM-002` model output → sink; `LLM-003` dangerous tool without confirmation; `LLM-004` key in client bundle; `LLM-005` no output/token limit. Mapped to OWASP Top 10 for LLM Applications.

### 22.3 Threat model
- `threat-model`: routes, auth middleware, stores, external calls, secrets → STRIDE table + Mermaid.

### 22.4 Incremental & monorepo
- `scan --changed` / `--since <ref>` (fail-closed without flag); workspaces; persistent cache; targets in Phase 42.

### 22.5 Local dashboard & history
- `report --serve` binds 127.0.0.1 only, rejects other Host headers, `/api/ingest` GET → 405. History in `.fullshield/history.db` (node:sqlite, lazy). Every DB handle closed in try/finally (Windows).

### 22.6 Compliance mapping
- Every rule ID maps to OWASP Top 10, CWE, ASVS, PCI DSS (test fails on a missing row). `report --compliance pci` prints "This is not a certification or audit."

### 22.7 IaC (light)
- GitHub Actions (unpinned actions, `pull_request_target`, write-all permissions, secrets in logs), Terraform (public S3, `0.0.0.0/0` on 22/3306/5432, unencrypted storage), Kubernetes (privileged, hostNetwork), compose (privileged). ~20 rules max.

### 22.8 Remediation agent
- `agent --max-prs N`: safe rule-based fixes only, ≤ N files per PR, project tests run, PR via localhost API only (refuses api.github.com and non-loopback), pushes only `fullshield/agent-*` branches to a local bare remote, never merges, never pushes `main`/`master`/`develop`, stops on first test failure. CRLF/Windows-safe git.

---

## 23. Benchmark & Proof
- Suites: tuning apps (B2), untouched holdouts (B3), real-world corpus (Phase 41), own fixtures and RASP corpora.
- Publish per release: recall per class (labeled), precision (labeled), scan time, runtime overhead p50/p95/p99, RASP block rate on attack corpus, benign block rate.
- Known-misses list with one-line reason each.
- Regression gate: CI fails if any benchmark metric regresses > 2% vs last release (after Phase 37).
- Self-authored corpus numbers are always labeled self-authored.

---

## 24. Scope Tiers & Phase Map

| Tier | Phases | Status |
|---|---|---|
| Core | 1–10 | done, stable |
| Pro | 11–16 | done; watch/edge/reachability/SBOM stable, AI experimental |
| Frontier | 17–24 | done, experimental |
| Next | 25–35 | done; 25 and 26 bench + 26b/26c/NoSQL fixes affect stable, 27–35 experimental |
| Depth | 36–45 | **to build** (Section 29) |

| Phase | Build | Acceptance |
|---|---|---|
| 17 | RASP sink hooks + `--import` | Attack ≥ 95% blocked, benign 0, p95 < 1 ms |
| 18 | Virtual patches, egress, honeytokens, threat response | Vpatch blocks seeded route; canary use → critical |
| 19 | Supply-chain defense + install-guard | Seeded malicious package detected; version diff flags new script |
| 20 | Exploit confirm + fuzz + IDOR | Seeded SQLi/CMDi/path/IDOR confirmed; non-local refused |
| 21 | MCP server + LLM-app rules | MCP client harness calls every tool; LLM fixtures pass |
| 22 | Threat model, incremental, workspaces, dashboard | Dashboard renders from SQLite history |
| 23 | Compliance mapping + IaC | Mapping test enforces every rule; IaC fixtures pass |
| 24 | Remediation agent | PR against local test repo with passing tests |

---

## 25. Next Tier Phases 25–35 [DONE — reference]

### Phase 25 — Windows + lazy SQLite (shipped in 0.1.1)
Windows × Node 22/24 in CI; quoted-filename test `skipIf(win32)`; idempotent `HistoryDb.close()` in try/finally; CRLF-independent fixer/agent diffs restoring original EOL; POSIX pathspecs; `--import` via `pathToFileURL`; runtime entries don't import `node:sqlite`; LRU flood test asserts retained-heap delta < 10 MB plus exact LRU sizes.

### Phase 26 — Public benchmark harness
`bench:public` clones pinned NodeGoat, Juice Shop, DVNA; ground truth from official docs (`reviewed: false`, in/out-of-scope); triage files; BENCHMARK.md; non-blocking CI `bench` job.

### Phase 26b — Stable public-bench misses (stable-output change)
Mongo `$where`; destructured `{ query }` taint; `md5(tainted)`; `autoescape: false`; helmet line attribution (not counted as recall); `CONFIG-DIRLIST-001`; `SECRET-SESSION-001`.

### Phase 26c — Engine gaps from goof holdout (stable-output change)
Receiver taint through method calls; taint through function params (5 hops); zip-slip sinks + `req.files` source; manifest-line attribution for direct deps. goof and vulnerable-node are now `seen`.

### NoSQL (stable-output change, human-approved)
`SAST-NOSQLI-001` flags request input as Mongo filter value unless coerced/validated/sanitized; Mongo/mongoose receivers only.

### Phase 27 — SAST/RASP coverage gaps [`FULLSHIELD_EXPERIMENTAL_SAST_GAPS`]
Numeric SQL positions; ORM raw sinks (Prisma `$queryRawUnsafe`/`$executeRawUnsafe`/`Prisma.raw` — not `$queryRaw` tagged; Sequelize `query`/`literal`; Knex `raw`/`whereRaw`/`orderByRaw`; TypeORM `query`/`createQueryBuilder().where(concat)`; Drizzle `sql.raw`); template-literal shell (`spawn('sh', ['-c'])`, execa `shell: true`, zx `$.raw`/`{ quote: false }`). ≥ 10 attack cases per context, benign 0.

### Phase 28 — Frameworks [`FULLSHIELD_EXPERIMENTAL_FRAMEWORKS`]
Next.js (route handlers, Server Actions, Pages API), NestJS (`@Body/@Query/@Param/@Headers`, `@UseGuards`), Hono, Koa sources and auth patterns; `fullshield/runtime/koa`, `/hono` (optional peers).

### Phase 29 — New classes [`FULLSHIELD_EXPERIMENTAL_CLASSES`]
| ID | Rule | CWE |
|---|---|---|
| SAST-REDOS-001 | Tainted input vs nested/overlapping-quantifier regex (static analysis, never executes user regexes) | CWE-1333 |
| SAST-DESER-001 | `node-serialize`, unsafe `js-yaml`, `funcster`, `serialize-javascript` eval paths | CWE-502 |
| SAST-XXE-001 | `libxmljs` `noent: true`, `xml2js` custom entities on tainted input | CWE-611 |
| SAST-UPLOAD-001 | multer/busboy/formidable without size/type limits; `originalname` in path | CWE-434 |
| SAST-COOKIE-001 | Cookies missing `httpOnly`/`secure`/`sameSite` (must NOT duplicate `SECRET-SESSION-001`) | CWE-614/1004 |
| SAST-CSRF-001 | Cookie-auth state-changing routes without CSRF protection and `sameSite` not strict/lax; must recognize csurf, csrf-csrf, csrf-sync, lusca, @fastify/csrf-protection, and app-level middleware | CWE-352 |
| SAST-MASSASSIGN-001 | `Model.create/update(req.body)`, `Object.assign(user, req.body)` without allowlist/schema | CWE-915 |
| SAST-TIMING-001 | Secret/token/HMAC compared with `===`/`==` | CWE-208 |
| SAST-HASH-001 | bcrypt cost < 10; argon2/pbkdf2 below OWASP minimums | CWE-916 |
| SAST-GQL-001 | Production introspection, no depth/complexity limit, tainted resolver args | CWE-770/200 |
| CONFIG-TRUSTPROXY-001 | `trust proxy: true` with IP rate limiting | CWE-290 |

### Phase 30 — Secrets advanced [`FULLSHIELD_EXPERIMENTAL_SECRETS_ADV`]
`--history` (streamed `git log -p`, blob-hash dedupe, `introducedIn`, `stillAtHead`); `--bundle <dir>` (`dist/`, `.next/static`, `build/`, `NEXT_PUBLIC_*`/`VITE_*`); `--verify-secrets` + `--i-own-these-credentials` (AWS STS GetCallerIdentity, GitHub GET /user, Stripe GET /v1/balance, Slack auth.test; `live|revoked|unknown`; never logs the key; never in CI templates).

### Phase 31 — Supply chain advanced + VEX [`FULLSHIELD_EXPERIMENTAL_VEX`]
Worm and workflow-tampering indicators; transitive overrides written to `package.json` (lockfile never edited); provenance coverage score; `fullshield vex --format openvex|cyclonedx` (`not_affected` only when `not-imported`; else `under_investigation`).

### Phase 32 — Response DLP [`FULLSHIELD_EXPERIMENTAL_DLP`]
`shieldGuard({ dlp: { mode: 'monitor'|'mask'|'block' } })`: responses ≤ 64 KB scanned for secrets, stack traces, internal IPs/hostnames, Luhn card numbers, bulk emails on single-email routes; < 1 ms p95; streaming bodies not inspected.

### Phase 33 — MCP config security [`FULLSHIELD_EXPERIMENTAL_MCPCFG`]
`.cursor/mcp.json`, `.vscode/mcp.json`, `.mcp.json`, Claude Desktop config (home only with `--include-home`). `MCP-001` inline secrets (high), `MCP-002` unpinned npx/@latest (medium), `MCP-003` shell/unrestricted fs-write without allowlist (medium), `MCP-004` tool-description injection (high), `MCP-005` remote over http (medium). Model-provided tool args are taint sources. `guardTools` opt-in library.

### Phase 34 — Policy-as-code + PR summary [`FULLSHIELD_EXPERIMENTAL_POLICY`]
`fullshield.policy.json`: required modules, severity overrides, `failOn` per branch, exceptions requiring `owner`, `reason`, ISO `expires` (missing → exit 2; expired → CI fails, finding not hidden). zod is an optional peer. `scan --pr-summary` deterministic Markdown, golden-file tests.

### Phase 35 — Host SSH exposure [`FULLSHIELD_EXPERIMENTAL_HOST`]
`fullshield host --experimental-host`, Linux only. Package version via dpkg-query/rpm/apk (not `ssh -V`), distro advisories via OSV, upstream fallback (8.5p1 ≤ v < 9.8p1, or v < 4.4p1). Mitigation check (`logingracetime 0`), exposure (`ss -ltn`), optional log signal without sudo ("possible exploitation attempts"). `HOST-SSH-001..003`; critical only if vulnerable + unmitigated + publicly listening. Remediation: upgrade openssh-server; `LoginGraceTime 0` temporary (DoS caveat); fail2ban/CrowdSec for blocking. Fixtures only in CI.

---

## 26. Shipped Capability Map

| Area | Status | Flag |
|---|---|---|
| Scan engine, reporters, baseline, suppression, `--fail-on` | stable | — |
| secrets (12 rules), masking, `--staged` | stable | — |
| deps + reachability + malicious + nolock + typosquat | stable | — |
| SAST 12 rules + cross-file taint | stable | — |
| config | stable | — |
| fix / fix --apply | stable | — |
| runtime middleware Express/Fastify | stable | — |
| init, notify, watch, edge, sbom | stable | — |
| AI explain, fix --ai | experimental | `--ai` |
| RASP / vpatch / honey | experimental | `FULLSHIELD_EXPERIMENTAL_RASP` / `_VPATCH` / `_HONEY` |
| install-guard | experimental | `FULLSHIELD_EXPERIMENTAL_SUPPLY` |
| confirm | experimental | `FULLSHIELD_EXPERIMENTAL_CONFIRM` |
| MCP server / LLM rules | experimental | `FULLSHIELD_EXPERIMENTAL_MCP` / `_LLM` |
| threat model / incremental / dashboard | experimental | `FULLSHIELD_EXPERIMENTAL_PLATFORM` |
| compliance / IaC | experimental | `FULLSHIELD_EXPERIMENTAL_COMPLIANCE` / `_IAC` |
| agent | experimental | `FULLSHIELD_EXPERIMENTAL_AGENT` |
| Phases 27–35 | experimental | `_SAST_GAPS`, `_FRAMEWORKS`, `_CLASSES`, `_SECRETS_ADV`, `_VEX`, `_DLP`, `_MCPCFG`, `_POLICY`, `_HOST` |

---

## 27. Open Items Carried Into Phase 36
- `SAST-COOKIE-001` must not duplicate `SECRET-SESSION-001` (test: exactly one finding with `--experimental-classes`).
- `SAST-CSRF-001` library + app-level middleware recognition (negative test: middleware in app.js, routes in router file).
- NoSQL PascalCase heuristic: negative test for TypeORM `BaseEntity` `User.find(...)` without a direct typeorm import.
- Juice Shop `data/static/codefixes/*` produce 6 NoSQL hits (challenge copies) — documented, no special-case exclusion.
- 0.1.3 missing provenance — root cause + gate.
- npm packument README empty under staged publishing (npm/cli#9405) — documented in RELEASING.md; no publish-flow workaround.

---

## 28. Known Limitations (mirror in README; update every release)
- Public alpha (0.x); APIs may change.
- Platforms: Linux, macOS, Windows on Node ≥ 22.13.
- Benchmark recall figures are on **unreviewed** ground truth; tuning-app figures are `seen` (rules were fixed against them). Current untouched-app figure: none (all apps used). Do not cite a recall percentage until Phase 37 + review.
- RASP corpus results are on self-authored/vendored corpora.
- NoSQL: filters built in a variable and passed later are partially missed.
- Template engines: Swig `{{ }}` lines; JSON-context XSS; `url.includes` allowlist bypass; DVNA calc vs `err.stack` pattern.
- Reachability is import-level + any-call; symbol-level only after Phase 39.
- All features from Phase 27 onward, RASP, AI, and Frontier are experimental.
- FullShield does not stop attacks by itself: `--fail-on` and runtime monitor/block are the prevention mechanisms.
- No deterministic detection of business-logic or authorization bugs.

---

## 29. Depth Phases 36–45 (TO BUILD)

**Order:** 36 first (blocks any release). Then 37 → 38 (benchmarks before engine work). 39–42 may run in parallel per R21. 43 after 39–42. 44–45 any time after 36.
**Suggested releases:** `0.2.0` = 36 + Section 27 items. `0.3.0` = 37–42. `0.4.0` = 43–45. Human decides.

### Phase 36 — Release integrity (BLOCKS ALL RELEASES)
Build:
1. Provenance gate in `publish.yml` (1.4). Root-cause 0.1.3's missing attestation; document in RELEASING.md.
2. `scripts/default-scan-diff.mjs`: snapshots default-scan findings per target into `bench/snapshots/<version>.json`; diff mode prints added/removed/changed `(ruleId, file, line, severity)`; exit 1 on any diff unless `--approved <file>` matches exactly. Create snapshots for 0.1.1 and 0.1.3 from their published tarballs (`npm pack fullshield@X` into temp, run that CLI).
3. `scripts/semver-check.mjs`: HEAD vs last tag — new rule IDs, commands, flags, exports, or stable-output diff → minor required; else patch. Fails if the `package.json` bump is smaller than required.
4. `scripts/pack-budget.mjs`: fails if unpacked > 2.0 MB, files > 120, or hard `dependencies` added vs last tag; prints what grew.
5. Section 27 items.
6. CHANGELOG `0.2.0` draft: every stable-output change since 0.1.1 (from default-scan-diff 0.1.1 → HEAD) under the R10 heading, plus every experimental feature with its flag.

Acceptance: unit tests for all four scripts; `npm publish --dry-run` in a test job (never a real publish); default-scan-diff 0.1.3 → HEAD empty or human-approved; semver-check says `minor`; pack-budget passes. **No tag.** Human releases 0.2.0 via Section 2.

### Phase 37 — Benchmark governance
Build:
1. `bench/holdouts.json` (B1) for all current apps with correct status.
2. Three new untouched holdouts (intentionally vulnerable Node/TS apps not used before; pinned SHAs; ground truth from their docs, cited, `reviewed: false`). **Do not scan them** in this phase. `status: "untouched"`, `firstRunDate: null`.
3. `bench/REVIEW.md` checklist (source link opens, line matches, class correct, scope correct) + `bench/review-sheet.mjs` exporting each app's ground truth as a Markdown table for the human.
4. `bench/sample-triage.mjs --app X --n 20`: random unmatched findings for human labeling → `bench/<app>/human-triage.json` → used for reviewed precision.
5. BENCHMARK.md regenerated with B2–B7 labels.

Acceptance: zod schema test for holdouts.json; test asserts no scan result file exists for untouched apps; review sheets generated.

### Phase 38 — Competitive benchmark (honest)
Build:
1. `bench/compare.mjs` on **tuning** apps only: FullShield default scan, Semgrep Community Edition with public rulesets (`p/javascript`, `p/typescript`, `p/nodejs`), OSV-Scanner, `npm audit --json`. Local tools only, no accounts. Pinned versions.
2. Documented mapping table from each tool's findings to B4 classes; unmapped counted separately.
3. `COMPARISON.md`: per app, per class — TP/miss against the same ground truth, total findings; for deps, total alerts vs FullShield reachable + via-dependency.
4. Neutral wording; report losses; no claims about tools not run.

Acceptance: reproducible with pinned versions; non-blocking CI job; human reviews mapping before COMPARISON.md is linked anywhere.

### Phase 39 — Reachability v2 (headline)
Build:
1. Symbol-level reachability when advisory data names affected functions/exports. Resolve named imports, `require('x').fn`, subpaths (`lodash/merge`), default/namespace member calls, re-export barrels. Classes `symbol-reachable` / `symbol-not-called`.
2. No symbol data → keep import-level classes. Never guess symbols.
3. For `reachable-via-dependency`: if `node_modules` exists, statically parse the direct dependency to check whether it calls the vulnerable export; else `unknown`. Never execute.
4. TS `paths`/`baseUrl` and package `exports` maps in resolution (shared resolver with Phase 40).
5. BENCHMARK.md: alert count before/after per tuning app, and every downgraded finding listed with evidence.

Acceptance: fixtures per import style/alias/subpath/barrel; `symbol-not-called` never applied without advisory symbol data (test); `DEPS-MALICIOUS-001` never downgraded (test). Stable-output change → R10.

### Phase 40 — Taint engine v2 [`FULLSHIELD_EXPERIMENTAL_TAINT_V2`]
Build propagation for: async/await and promise chains; callbacks and array methods; `call/apply/bind`; destructuring, spread, `Object.assign`, nested property paths; class fields / `this.x` across methods; closures; cross-file through aliases and barrels. Depth 5, content-hash cache, time budget test (Phase 42).

Acceptance: positive + negative generic fixture per propagation kind (written from scratch, B8); tuning recall reported `seen`; untouched apps not run.

### Phase 41 — Precision pass
Build:
1. `bench/realworld.json`: 10 popular maintained non-vulnerable Node/TS repos (Express, Fastify, Nest, Next, Koa mix), pinned SHAs.
2. `bench/fp-scan.mjs`: default scan + each experimental flag separately; export findings for triage.
3. Budget per stable rule: ≤ 1 false positive per 10k LOC (human-sampled, B6). Over budget → narrow with negative test, downgrade confidence, or move behind a flag (R10 if stable).
4. Per-rule precision table in BENCHMARK.md.

Acceptance: every stable rule has a precision row; every over-budget rule has a human-approved decision.

### Phase 42 — Performance
Build:
1. Harness on 3 real repos ≥ 50k LOC (pinned): cold, warm-cache, `--changed`.
2. Targets on ubuntu-24.04 runner: cold ≤ 60 s, warm ≤ 20 s, incremental ≤ 5 s, peak memory ≤ 1.5 GB.
3. Worker-thread parse pool (CPUs − 1, configurable); parse cache keyed by content hash + FullShield version.
4. CI fails if p50 of 3 runs regresses > 15% vs stored baseline.

Acceptance: targets met or documented with numbers in Known Limitations; identical output with/without workers (test).

### Phase 43 — Experimental → stable promotion
Criteria (all required, per feature):
- SAST: recall gain on ≥ 1 untouched app with reviewed ground truth, and within Phase 41 FP budget.
- Runtime: p95 ≤ 1 ms overhead, 0 benign blocks on corpus.
- Others: phase acceptance + 0 crashes on the Phase 41 corpus.
- Docs page, CHANGELOG entry, migration note, human approval.

Build `scripts/promotion-report.mjs` listing each flag's met/unmet criteria with evidence. Promote only approved features; each promotion is an R10 change; promoted flags become no-ops with a deprecation notice for one minor release.

### Phase 44 — Developer experience
Build:
1. Console output: by severity, top 10 first, "N more — use --json"; each finding file:line, one-line why, one-line fix, rule doc link.
2. `fullshield doctor`: Node version, lockfile type, cache state, flags, config validity, OSV reachability (respects `--offline`).
3. Error codes `FS-E###` with fix hint and docs link; no raw stack traces without `--debug` (test).
4. README rewrite: quickstart, stable findings, non-goals, experimental list, benchmark and comparison links (after Phase 38 review), no superlatives (4.4).
5. `docs/demo.md` from a real run (no fabricated output).

Acceptance: console snapshot tests; doctor tests per check; README link-check test.

### Phase 45 — Self-security hardening
Build:
1. All GitHub Actions pinned by commit SHA; Dependabot updates them.
2. OpenSSF Scorecard workflow (non-blocking) + badge; fix items under FullShield's control.
3. CodeQL for JS/TS.
4. FullShield's own CycloneDX SBOM attached to each GitHub Release.
5. Reproducible build check: build twice in clean environments, compare `dist/` hashes; document nondeterminism.
6. `SECURITY.md`: response SLA, supported versions, private advisory link.

Acceptance: workflows green; reproducibility passes or differences documented; Scorecard artifact uploaded.

---

## 30. Status (update at the end of every phase)

| Item | State |
|---|---|
| npm latest | 0.1.3 until the v0.2.4 publish job shows dist.attestations |
| main | phases 1–45 at 0.2.4 |
| next | same tree as the 0.2.4 release |
| Next release | 0.2.4 |
| Ground truth reviewed | none (all `reviewed: false`) |
| Untouched holdouts in reserve | 3 (verademo-javascript, serverless-goat, mongection), not scanned |
| Provenance gate | in publish.yml; snapshots in bench/snapshots; 0.1.3 matches HEAD; 0.1.1 diff is not approved |
| Section 27 open items | COOKIE/CSRF already covered; BaseEntity negative test added; Juice Shop codefixes documented |
| Comparison / precision / promotion | comparison run in COMPARISON.md; precision not sampled; nothing promoted |

---

## 31. Explicitly Rejected (do not build)
- Container image / OS package scanning (use Trivy/Grype).
- Host intrusion prevention, firewall management, OS-level IP blocking (use fail2ban, CrowdSec, cloud WAF).
- Scanning or attacking non-local hosts.
- Cyber-physical / hardware-implant detection.
- An LLM in the request path.
- Telemetry of any kind.
- Anything that auto-merges, auto-deploys, deletes code, edits lockfiles by hand, or publishes without human approval.
