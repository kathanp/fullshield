# FullShield — Build Spec for Cursor (full, rev 2026-10-21f)

> Package: `fullshield` on npm (owner `kathan2404`). Repo: https://github.com/kathanp/fullshield (public, MIT).
> Language: TypeScript (strict). Runtime: Node.js ≥ 22.13. Distribution: one npm package (CLI + library + runtime middleware).
> Live on npm: `1.0.1` is latest (published 2026-10-21T02:43:27Z with provenance). `0.1.3` was **published WITHOUT provenance — must never happen again**. Placeholders `0.0.0-stage`, `0.0.1` deprecated. `0.1.2` was never published.
> This file is the only spec. The 2026-10-14 draft (`SECURITY_SCANNER_SPEC (1).md`) is deleted. Its design lives here; Section 33 lists the few requirements that draft stated and this file had shortened. Later text wins where the draft disagreed.
> [X] Complete: phases 1–55 and 57–94. Phase 56 is not in 1.0.1 (blocked on R15). Phase 65 is coded; the 5-second nest/undici target is still unmet. Experimental phases stay off unless their flag is set. Phases 36–45 are reference, not a queue.
> **Current queue is Section 45** for autopilot runs. The 1.2.0 version scope is there. 1.0.1 is published. Section 47 phases 108–250 are in that same 1.2.0 scope, after 107. Section 43 is the finished 2026-10-19 run; Section 42 adds the quality gate (R24, Phase 94) and the definition of done for every remaining phase. During an autopilot run, Section 45 R26 item 4 overrides Section 40.5: no report file is written. Outside a run, Section 40.5 report-file rules still apply. Earlier queue: Section 40 (2026-10-19, lanes A/B/C). Section 36 is the 2026-10-18 record. Leadership phases 76–93 are in Section 39 and are in this tree behind their flags. Advanced phases 60–75 are in Section 37; Phase 47 has an addendum (47.1) there that is part of its acceptance. Section 38 is the production-reliance stance (not a queue). Section 41 lists human-only work. Phase 56 is not in this release.

---

## 0. HARD RULES (read first, apply always, no exceptions)

Breaking any rule below = stop work and report to the human. Do not "fix forward" around a rule.

### 0.1 Authority
- [ X ] **R1.** The human approves: tags, publishes, merges to `main`, ground-truth reviews, test edits, threshold changes, and moving any feature from experimental to stable. Cursor never does these without an explicit "go" in the current message.
- [ X ] **R2.** If a human instruction conflicts with this spec, ask before acting. If this spec conflicts with code comments or other docs, this spec wins.

### 0.2 Tests and evidence
- [ X ] **R3.** Never modify, delete, skip, or weaken an existing test, fixture, `expected-findings.json`, `ground-truth.json`, or `triage.json` to make anything pass. If a test is wrong, stop and explain; the human decides.
- [ X ] **R4.** Write the failing test first (red), then implement (green). Every rule has ≥ 1 positive and ≥ 1 negative fixture.
- [ X ] **R5.** No stubs that pretend to work. A feature that can't meet its acceptance criteria ships behind its experimental flag or is left out.
- [ X ] **R6.** Never invent vulnerability data. Dependency advisories come only from OSV (https://api.osv.dev) or `npm audit --json`. Never invent finding counts, benchmark numbers, or tool comparisons.
- [ X ] **R7.** Cursor never grades its own work as final. Any number that appears in README, CHANGELOG, BENCHMARK.md, COMPARISON.md, or a release note is either from human-reviewed ground truth or labeled `unreviewed`.
- [ X ] **R8.** Paste real command output. Never summarize a failing run as passing. For long output, paste the summary table plus every failure in full.
- [ X ] **R3a. Never silence a rule.** Never make a shipped rule stop reporting (no-op `ctx.report`, early `return`, commented-out sink, narrowed matcher, raised threshold, added suppression) to change a count, a diff, or a test result. Changing what a shipped rule reports is an R10 change and needs its own phase, a failing test, and human approval. Doing it in passing is a session stop (S7).
- [ X ] **R8a. Fixture reclassification:** an attack fixture may move to the benign corpus only if (a) it provably cannot change the sink's structure in its context, AND (b) a genuine breakout payload for that same context is added to the attack corpus and is detected. Document both in the fixture file. Report to the human (counts as R3 decision).

### 0.3 Stable behavior
- [ X ] **R9.** "Stable output" = default `fullshield scan --json` findings `(ruleId, file, line, severity)` on `test/fixtures/vulnerable-app`, `test/fixtures/clean-app`, and every app in `bench/`. `scripts/default-scan-diff.mjs` compares against the snapshot of the last published version.
- [ X ] **R10.** Any stable-output change requires: (a) human approval before merge, (b) a CHANGELOG entry under **"New/changed stable findings — may change CI results; use --update-baseline"**, (c) a **minor** version bump (R16).
- [ X ] **R11.** Every new feature ships behind `FULLSHIELD_EXPERIMENTAL_<NAME>=1` and/or `--experimental-<name>`, off by default. Promotion to stable follows Phase 43 only.
- [ X ] **R12.** clean-app produces 0 findings of any severity in default scan, always.

### 0.4 Code and dependencies
- [ X ] **R13.** No new hard runtime `dependencies`. New libraries go in optional `peerDependencies` (`peerDependenciesMeta.optional: true`), lazy-loaded with `import()` only by the command that needs them, with a clear "install X to use this feature" error.
- [ X ] **R14.** Runtime entry points (`fullshield/runtime*`) import zero scanner code and never load `node:sqlite` at import time. `node --import fullshield/runtime/register -e "1"` prints nothing on stderr.
- [ X ] **R15.** Never execute scanned code. Never install analyzed packages. Never send code to a network service without an explicit opt-in flag (`--ai`; `--verify-secrets` + `--i-own-these-credentials`). Never contact hosts other than OSV, registry.npmjs.org, user-configured webhooks/AI providers, or localhost.

### 0.5 Versioning
- [ X ] **R16.** 0.x semver: **patch** = bug fixes only, no new features, no stable-output change. **minor** = any new feature (even experimental), new rule ID, new command/flag/export, or stable-output change. Enforced by `scripts/semver-check.mjs` (Phase 36).
- [ X ] **R17.** Never reuse, decrease, or delete a version. Published versions are permanent. Fix forward only.
- [ X ] **R16a.** 1.x semver: **patch** = bug fixes and documentation corrections, including a correction to `docs/stability.md` that moves a row out of Stable when that row was only ever produced by an experimental flag. No new feature, rule ID, command, flag, or export, and no default-scan output change. **minor** = new feature, rule ID, command, flag, or export, or a default-scan output change that adds findings. **major** = removing or changing anything that is Stable in `docs/stability.md` and was produced without a flag. `scripts/semver-check.mjs` applies R16 below 1.0.0 and R16a from 1.0.0 on.

### 0.6 Workflow
- [ X ] **R18.** All work on `next` (or `phase-N` worktrees off `next`). `main` only via PR from `next`, full CI matrix green, human approval.
- [ X ] **R19.** Commit message per phase: `phase-N: <summary>`. Never mix phases in one commit.
- [ X ] **R20.** Before every commit: `npm run verify` passes locally. Before every merge into `next`: `npm run verify` + `node scripts/default-scan-diff.mjs` (empty unless R10 approved).
- [ X ] **R21.** Parallel subagents: one git worktree per phase on branch `phase-N`. Integrate into `next` sequentially in numeric order; full verify + diff after each merge. Shared files (CLI registration, rule registry, compliance map, CHANGELOG, README) are appended to, never rewritten.
- [ X ] **R22.** Every platform-sensitive test (paths, filenames, shell, line endings) must pass on Linux, macOS, Windows, or use `it.skipIf(process.platform === 'win32')` with a comment giving the reason. No `"` in filenames, use `path.join`, never hardcode `/`. `--import` paths use `pathToFileURL(...).href`.

### 0.7 Stop conditions
**Scope of a stop (R23).** A stop condition stops the **phase** that hit it, not the session. Cursor parks that phase on its `phase-N` branch, writes the full 0.8 report for it into the day's report file (Section 40.5), and moves on to the next queue item that does not depend on the parked one. The human decides parked items later.

The **session** stops only for:
- the `next` baseline itself is red (S4 on `next`, not on a phase branch),
- S6 (a publish would lack provenance, or the pack budget is exceeded on `next`),
- S7 (an instruction would require breaking R1–R22),
- any R1 action (tag, publish, merge to `main`, ground-truth review, test edit, threshold change, promotion). These are never done. They are listed under "Needs human decision" and the work continues.

Even when the session stops, Cursor writes the report file first.

Conditions:
- [ X ] S1. Stable-output diff not pre-approved.
- [ X ] S2. Any existing test/fixture/ground-truth needs editing.
- [ X ] S3. A phase can't meet acceptance criteria.
- [ X ] S4. Same CI failure twice in a row.
- [ X ] S5. Coverage within 2 points of any threshold.
- [ X ] S6. A publish would lack provenance, or `npm pack` exceeds budget (Phase 36).
- [ X ] S7. Any instruction would require breaking R1–R22.

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
   - [ X ] `scan test/fixtures/vulnerable-app --json` → every ID in `expected-findings.json` present.
   - [ X ] `scan test/fixtures/clean-app --fail-on high` → exit 0.
   - [ X ] `scan test/fixtures/vulnerable-app --fail-on high` → exit 1.
   - [ X ] `scan ... --sarif out.sarif` → validates against SARIF 2.1.0 schema.
   - [ X ] No unmasked fake secret in any output format.
5. **Mutation smoke** (`scripts/mutation-smoke.mjs`): disable each SAST/secrets rule's detection function (and the extra targets list) → its tests must fail. If they still pass, the tests are fake → fail.
6. **default-scan-diff** (Phase 36) — empty, or exactly matches the approved diff file.
7. Summary table: phase, tests, coverage lines/branches, implemented modules, expected vs found, vulnerable-app finding count, clean-app high/critical, attack/benign corpus results. Then phase acceptance criteria.

`verify:phase N` = steps 1–7 plus that phase's acceptance criteria.

### 1.3 CI (`.github/workflows/ci.yml`)
- [ X ] Push to `next`: one job `verify (ubuntu-24.04, node 24)`.
- [  ] PR to `main` and push to `main`: full matrix `ubuntu-24.04`, `macos-latest`, `windows-latest` × Node 22, 24.
- [ X ] Uploads coverage and SARIF artifacts. Non-blocking `bench` job uploads BENCHMARK.md.
- [ X ] Actions pinned by commit SHA (Phase 45). Never `ubuntu-latest` for jobs.
- [  ] `main` branch protection requires the 6 matrix jobs by exact name. When job names change, update required checks in the same PR, after the new jobs have reported once.

### 1.4 Publish (`.github/workflows/publish.yml`)
- [ X ] Trigger: tags `v*` only. Node 24. `npm install -g npm@12.2.0` (trusted publishing needs npm ≥ 11.5.1; the pin stops a later npm major from changing pack JSON or the OIDC client). The probe does not save the GitHub OIDC token. Staging requests a new one immediately before the exchange. Staging turns on sigstore `fetchOnConflict` and gives the Rekor request 120 seconds, so a 409 reuses the existing transparency-log entry. It still refuses to stage without provenance.
- [ X ] `permissions: id-token: write, contents: read`. No `NPM_TOKEN`. No GitHub Environment. Trusted publishing (OIDC) configured on npmjs.com for `kathanp/fullshield`, workflow `publish.yml`.
- [ X ] Steps: `npm ci` → `npm run verify` → `node scripts/semver-check.mjs` → `node scripts/pack-budget.mjs` → `npm publish --provenance --access public` → **post-publish gate**: poll `npm view fullshield@$VERSION dist.attestations` (up to 10 min; staged approval may delay) and fail loudly if empty.
- [ X ] Staged publish approval on npmjs.com stays ON (human 2FA approves every publish).
- [ X ] Never edit the staged manifest or inject README text into it (Cloudflare blocks it; npm/cli#9405 tracks the empty packument README).

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

- [ X ] **B1. Holdout registry** `bench/holdouts.json`: every benchmark app `{name, repo, sha, status: "tuning" | "seen" | "untouched", reviewed: bool, firstRunDate}`.
- [ X ] **B2. Tuning apps** (current: NodeGoat, Juice Shop, DVNA, snyk-labs/nodejs-goof, cr0hn/vulnerable-node): rules may be fixed from their misses. Their recall is labeled `seen`, never a headline.
- [ X ] **B3. Untouched apps:** scanned exactly once per release, after code freeze. No rule change may cite an untouched app's result. After a release uses it, it becomes `seen`. Keep ≥ 2 untouched apps in reserve at all times.
- [ X ] **B4. Ground truth:** built only from each app's own published vulnerability docs; every entry cites its source; `"reviewed": false` until the human flips it. Each entry has `inScope` (class FullShield claims to detect statically: sqli, nosqli, cmdi, path, xss, ssrf, redirect, eval, jwt, crypto, proto, secrets, deps, config) or is out-of-scope with a one-line reason. Recall is computed on in-scope entries only.
- [ X ] **B5. Matching:** same class + same file + line ±3. Moving the reported line of an existing finding is never a recall gain.
- [ X ] **B6. Precision:** every unmatched finding triaged `realIssue | falsePositive | unsure` with a reason. Precision is labeled `self-triaged` until the human samples ≥ 20 findings per app and confirms.
- [ X ] **B7. Headlines:** only untouched-app recall from reviewed ground truth may appear in README or release notes. All else stays in BENCHMARK.md with labels.
- [ X ] **B8. Never** copy benchmark-app code into fixtures. Fixtures reproducing a pattern are written from scratch.

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
- [ X ] Does NOT find business-logic/authorization bugs (IDOR, broken access control) deterministically. Routes without auth middleware are flagged *suspicious*, nothing more.
- [ X ] Does NOT replace a penetration test.
- [ X ] Does NOT auto-delete code, auto-merge, or auto-deploy, ever.
- [ X ] Does NOT stop OS-level or network-service exploits (e.g. OpenSSH regreSSHion, kernel bugs). `host` only reports exposure.
- [ X ] Is NOT a WAF, firewall, DDoS mitigation, or host intrusion prevention system. Use a CDN/WAF, fail2ban, or CrowdSec.
- [ X ] Does NOT scan container images or OS packages. Use Trivy or Grype.
- [ X ] Does NOT run attacks against any host other than localhost or a container FullShield started.
- [ X ] Does NOT detect cyber-physical or hardware attacks (ICS/SCADA sabotage, hardware implants, firmware). The closest in-scope analog is npm supply-chain heuristics — software only.
- [ X ] JS/TS only.

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
Taint: sources `req.body/query/params/headers/cookies`, destructured request params, `process.argv` (+ framework sources behind flags). Propagation: assignment, concat, template literals, method-call receivers, function params and returns (same file and cross-file via `require`/`import`, depth 5). Phase 51 follows a SQL string or Mongo filter returned from a helper in another file. Sanitizers are sink-specific: parameterized query APIs (SQL), zod/joi/yup `.parse` result only, `validator.*` only for the check that function actually performs, `path.resolve` + `startsWith(base)` (path), `encodeURIComponent` (URL/redirect only), HTML escape/DOMPurify (XSS only). `JSON.parse`/generic `parse` never clear taint. A schema that only checks "this is a string" does not clear SQL concatenation. Parameterized queries are never flagged. Phase 53 may add class-validator on the same rule: the schema clears a finding only for the class that schema constrains.

---

## 7. Module Details

### 7.1 deps
- [ X ] Parse `package-lock.json` (v2/v3 + dependencies-tree fallback), `pnpm-lock.yaml`, `yarn.lock` (classic) → packages and dependency edges. Unknown/edge-less formats → `edgesKnown: false` → `reachability-unknown` (never a silent downgrade).
- [ X ] OSV `/v1/querybatch` (ecosystem npm) then per-ID details. Cache `~/.cache/fullshield/osv/`, 24h TTL. `--offline` = cache only; never invents advisories.
- [ X ] `DEPS-NOLOCK-001` (info) when manifest has no lockfile; exact pins still queried.
- [ X ] `DEPS-MALICIOUS-001`: OSV `MAL-` or malicious classification → always critical, never downgraded. Remediation: remove package, delete node_modules, reinstall, rotate credentials.
- [ X ] Reachability (stable): `reachable` (imported + called; kept), `imported-not-called` (−1), `reachable-via-dependency` (lockfile path from a production-imported direct dep; kept; path shown e.g. `express > body-parser > qs`), `not-imported` (−2, only when edges known), `reachability-unknown` (kept). Dev-only vulns → info `dev-only` unless production code imports the package. Test-file imports are not roots.
- [ X ] Direct dep findings attributed to the `package.json` line.
- [ X ] Fix: minimum non-vulnerable version from OSV ranges; bump safe if same major, unsafe otherwise. Transitive with no parent fix → `dependency-override` (unsafe) written to `package.json` `overrides` / `pnpm.overrides` / `resolutions`; never edits the lockfile; prints "run npm install".
- [ X ] Typosquat: Levenshtein ≤ 1 vs a static popular list, direct deps only, min length 4, name not in top-packages list → medium, low confidence.

### 7.2 secrets
- [ X ] Rules: AWS, Stripe, GitHub, Slack, Google, OpenAI/Anthropic-style keys, PEM private keys, DB URLs with inline passwords (placeholders like `<password>` skipped), hardcoded JWT secrets, generic high-entropy assignment (entropy > 4.5, length ≥ 20, key/secret/token/password names; low confidence), committed `.env*` (except `.env.example`, `.env.backup` honey decoy), `SECRET-SESSION-001` hardcoded express-session secret.
- [ X ] String-literal concatenation folded before matching. Masking (`first4 + ****`) before any Finding exists; raw secrets never leave the module (tested in every output format).
- [ X ] Remediation always: rotate the key; removing it from code is not enough because it stays in git history.
- [ X ] `--staged` scans only the git index (pre-commit).

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
- [ X ] Express app factory and no helmet → medium (line-attributed to `express()` or commented-out helmet).
- [ X ] `cors({ origin: '*', credentials: true })` or reflective origin → high.
- [ X ] Auth routes without a rate limiter → medium.
- [ X ] `express.json()` without limit → low.
- [ X ] Error handler sending `err.stack` → medium.
- [ X ] `serveIndex()` → `CONFIG-DIRLIST-001`.
- [ X ] Dockerfile: no USER / root, `FROM *:latest`, `ENV *_KEY=`/`*_SECRET=` → medium/high.
- [ X ] Lockfile `hasInstallScript` → info.

### 7.5 runtime (stable middleware + experimental RASP)
- [ X ] Request context via `AsyncLocalStorage`.
- [ X ] Signature-based inspector (SQLi/XSS/path) — a stopgap, not a WAF; `monitor` default.
- [ X ] Sliding-window rate limiter for `authRoutes` (pluggable store), LRU caps (keys 10k, routes 1k, params 200, configurable).
- [ X ] Body size/depth/key limits.
- [ X ] Events never include raw bodies: rule id, path, IP, truncated masked sample.
- [ X ] Budget: < 1 ms p95 added latency on a typical JSON request (benchmark).
- [ X ] Runtime bundle tiny, no scanner imports (R14).

---

## 8. Fix Engine
- [ X ] `fix` = dry run, unified diffs.
- [ X ] `fix --apply`: refuse dirty git tree unless `--force` (which skips files with uncommitted changes); create branch `fullshield/fixes-<timestamp>` unless `--no-branch`; apply `safe: true` only unless `--unsafe`; snapshot each file's bytes before writing; run project tests if present; restore snapshots on failure (never `git checkout --`). Restores original line endings.
- [ X ] Safe: same-major bumps, JSON body limit, `Math.random` → `crypto.randomUUID()`/`randomBytes`, `.env` in `.gitignore`.
- [ X ] Unsafe (shown in dry run, `--unsafe` to apply): `helmet()` insertion, secret → `process.env.X` with rotate comment, major bumps, dependency overrides, code patches.
- [ X ] Never removes code blocks. Never deletes user files. Never edits lockfiles by hand.

---

## 9. Prevention (CI + hooks)
`fullshield init` generates:
- [ X ] `.github/workflows/fullshield.yml`: `scan --sarif` on PRs, SARIF upload, `--fail-on high`.
- [ X ] `.gitlab-ci.yml` snippet: same, JSON artifact.
- [ X ] `.github/workflows/fullshield-watch.yml`: daily `watch`.
- [ X ] `.fullshield/pre-commit.sh` (plain shell): `scan --modules secrets --staged`.
- [ X ] `fullshield.config.json`:
```json
{
  "modules": ["deps", "secrets", "sast", "config"],
  "failOn": "high",
  "ignore": ["dist/**", "**/*.test.ts"],
  "baseline": ".fullshield-baseline.json",
  "notify": { "slackWebhookEnv": "FULLSHIELD_SLACK_WEBHOOK" }
}
```
- [ X ] Baseline (`--update-baseline`): CI fails only on new findings.
- [ X ] Inline suppression: `// fullshield-ignore SAST-SQLI-001: reason` (reason required; missing reason does not suppress).
- [ X ] `--verify-secrets` is never placed in generated CI templates.

---

## 10. Reporting & Notification
- [ X ] Console: grouped by severity, file:line, one-line fix each.
- [ X ] JSON: `Finding[]` + summary counts + metadata (version, duration, modules).
- [ X ] SARIF 2.1.0, schema-validated; `codeFlows` from traces.
- [ X ] Markdown / HTML (escaped, secrets masked).
- [ X ] `--pr-summary` (experimental): deterministic Markdown of new findings vs baseline; text only, never posts.
- [ X ] Notifiers: Slack webhook, generic webhook, SMTP; creds from env only; summaries and masked data only. Last scan stored in `.fullshield/last-scan.json` (always ignored by the walker).

---

## 11. Security of the Package Itself (non-negotiable)
- [ X ] No install/postinstall scripts.
- [ X ] Hard runtime deps ≤ 6 (currently: commander, ignore, picocolors, @typescript-eslint/typescript-estree). Optional peers: express, fastify, koa, hono, zod, @modelcontextprotocol/sdk. Lockfile committed.
- [ X ] Publish only from CI via trusted publishing with `--provenance`; post-publish attestation gate (S6). No long-lived npm tokens. 2FA on npm and GitHub. Staged approval on.
- [ X ] Tarball: `dist/` (no `.map`), README, LICENSE, CHANGELOG, templates, rules. Budget: unpacked ≤ 3.0 MB, ≤ 320 files (Phase 36, raised for 1.2.0).
- [ X ] Scanned code is never executed. Parse only.
- [ X ] Network: OSV, registry.npmjs.org (supply-chain features), user-configured webhooks/AI providers, localhost (confirm/agent/dashboard). `--offline` available.
- [ X ] Dogfood: FullShield scans its own repo in CI.
- [ X ] No telemetry.

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
- [ X ] `test/fixtures/vulnerable-app/`: at least one instance of every stable rule, e.g.:
```ts
app.get('/user', (req, res) => db.query("SELECT * FROM users WHERE id = " + req.query.id)); // SQLI
app.get('/file', (req, res) => res.sendFile(req.query.name));                                // PATH
app.post('/run', (req, res) => exec(`ping ${req.body.host}`));                                // CMDI
const token = Math.random().toString(36);                                                    // CRYPTO
const AWS_KEY = "AKIA" + "XXXX…";                                                            // SECRETS (fake, concatenated)
```
- [ X ] `clean-app/`: same features written safely; 0 findings (R12).
- [ X ] Fake secrets are always concatenated or generated at test time; never realistic-looking committed keys (push protection).
- [ X ] RASP corpora: attack payloads (vendored PayloadsAllTheThings, MIT attribution) + benign corpus (O'Brien, "SELECT your seat", dotted paths, URLs in comments). Each attack fixture records its sink context. Target ≥ 95% blocked, 0 benign blocked.
- [ X ] Platform rules per R22.

---

## 14. Definition of Done (v1.0)
- [  ] Core stable with tests green; every experimental feature either promoted via Phase 43 or still flagged.
- [ X ] Linux, macOS, Windows supported.
- [  ] 50k-LOC scan ≤ 60 s cold (excluding network) — Phase 42.
- [ X ] clean-app 0 findings.
- [  ] Recall on ≥ 2 untouched apps with **reviewed** ground truth published (B7).
- [  ] Per-rule precision within Phase 41 budget.
- [ X ] README lists non-goals and Known Limitations (Section 28).
- [  ] Every published version has provenance; dogfood passes in CI.

---

## 15. Post-launch Maintenance
- [  ] Weekly rule review; OSV is live, SAST rules need upkeep.
- [  ] Every user false-positive report → benign fixture + regression test.
- [  ] Every missed-attack report → attack fixture + regression test.
- [  ] Issue templates: bug, false positive, missed attack, new rule.
- [ X ] `CONTRIBUTING.md` is the rule-authoring guide.

---

## 16. All-in-One Packaging
- [ X ] One install: `npm i -D fullshield` / `npx fullshield`. Never split into separate packages.
- [ X ] Subpath exports:
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
- [ X ] Runtime path tiny (R14); test bundles runtime and asserts the bundle is under 50 KB and imports no parser.
- [ X ] Heavy modules (SAST parser, YAML, SQLite, MCP SDK, zod) loaded with `import()` only when used.
- [ X ] One version, one CHANGELOG.

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
- [ X ] CDN/WAF detection by headers (`cf-ray`, `server: cloudflare`, `x-amz-cf-id`, `x-served-by`, …); none → high.
- [ X ] TLS validity, expiry < 21 days → warn, HTTP → HTTPS redirect.
- [ X ] Headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy.
- [ X ] Probes (GET/HEAD only, ≤ 15 requests, 1 req/s): `/.env`, `/.git/HEAD`, `/package.json`, `/debug`, `/server-status`.
- [ X ] Only user-passed URLs. No crawling, port scanning, or payload fuzzing. README: only scan sites you own or are authorized to test.

---

## 17. Advanced Engine (non-AI)

### 17.1 Cross-file taint
- [ X ] Module graph from relative `require`/`import`, `require(x).Export`, `new Ctor()` methods, `this.method = fn`; TS path aliases and barrels in Phase 39/40.
- [ X ] One finding per source→sink with full `trace`; SARIF `codeFlows`.
- [ X ] Depth 5; per-file cache keyed by content hash.

### 17.2 Dependency reachability
- [ X ] See 7.1. Phase 39 adds symbol-level reachability where advisory data names affected functions; never guesses symbols.
- [ X ] Headline feature in README: turns hundreds of lockfile alerts into the ones that matter.

### 17.3 SBOM
- [ X ] `fullshield sbom --format cyclonedx` → CycloneDX 1.5 with vuln references. Licenses only when present in data; never invented.

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
- [ X ] Code wrapped in delimited blocks; system prompt marks it untrusted.
- [ X ] `AI-INJECT-001` (medium): comments containing phrases aimed at AI reviewers ("ignore previous", "mark as safe", "AI reviewer") — basic heuristic.
- [ X ] Model never gets acting tools; deterministic code performs all actions.

### 18.3 AI features (all experimental)
| Mode | Status | Guardrail |
|---|---|---|
| `scan --ai explain` | experimental, user-facing | Explanation text only; never shows a verdict |
| `fix --ai` | experimental, user-facing | Verify loop: temp copy → rescan (finding gone, no new) → tests → keep only if all pass; max 2 attempts; reviewable diff; never writes user tree |
| `--ai triage`, `--ai logic` | internal only (`FULLSHIELD_AI_INTERNAL=1`); rejected by CLI | Live smoke results not good enough to advertise (see benchmarks/AI-REPORT.md) |

### 18.4 Runtime anomaly detection (statistical, no LLM)
- [ X ] `shieldGuard({ anomaly: { learnMinutes } })`: per-route baselines; flags 401 spikes, new param names, 404 bursts. LRU-capped.
- [ X ] Optional `ai summarize` turns a day of those events into a short incident summary. Offline, batch, opt-in. It is not on the request path.

### 18.5 AI tests
- [ X ] Recorded (VCR-style) fixtures in CI; `npm run test:live-ai` is opt-in, not in verify/CI.

---

## 19. Frontier: Runtime Self-Protection (RASP) [experimental]

### 19.1 Sink hooking
- [ X ] CommonJS via `Module._load` hooks; ESM via `module.register()` loader hooks; `diagnostics_channel` where available.
- [ X ] Hooked sinks: `pg`, `mysql2`, `better-sqlite3`, `node:sqlite` (only if the app imports it), `mongodb`, `mongoose`, ORM raw APIs (Phase 27), `child_process.*`, `fs.*`/`fs/promises`, `http(s).request`, `fetch` (undici), `axios`, `vm`, `res.redirect`, template render calls.
- [ X ] Activation: `node --import fullshield/runtime/register app.js` or `import 'fullshield/runtime/auto'` first. Docs use the package specifier or `file://` URLs.
- [ X ] Fail-open: hook errors emit `RASP-FAIL-OPEN-001` and call the original.

### 19.2 Structure-change detection
For each sink call, collect request input strings (query, body, params, headers, cookies, flattened). For each input appearing in the sink argument:
- [ X ] **SQL:** dialect-aware tokenizer; input spanning more than one literal token (keywords, operators, comments, quotes) → injection. Numeric positions: anything beyond a single numeric token → injection.
- [ X ] **Shell:** POSIX tokenizer; input introducing `;`, `|`, `&&`, `$()`, backticks, redirection, or new arguments → injection.
- [ X ] **Path:** resolved path escapes the joined base, or null bytes → block.
- [ X ] **NoSQL:** object with `$` operators where a scalar was expected → block.
- [ X ] **SSRF:** resolve at connect time; block private/loopback/link-local/metadata (incl. IPv6 brackets, `::ffff:` mapped, decimal/octal/hex/short IPv4, trailing dots) when host came from input; re-check redirects; pin resolved IP.
- [ X ] **Prototype pollution:** block `__proto__`, `constructor`, `prototype` keys; optional `Object.freeze(Object.prototype)` mode.

### 19.3 Virtual patching
- [ X ] `scan --emit-virtual-patches` → `.fullshield/vpatches.json` `{ruleId, file, line, sink, route}`; runtime blocks only those route/sink pairs; reverts when findings disappear.

### 19.4 Egress control
- [ X ] `egress.allow` exact hosts and `*.suffix` (subdomain-only; apex and suffix confusion denied) plus IP literals.

### 19.5 Honeytokens
- [ X ] `honey init`: decoy `.env.backup` with obviously-fake canaries (`FULLSHIELD-HONEY-CANARY-NOT-A-CLOUD-KEY`, `fullshield-honey-db-canary://local`), decoy routes (`/admin.php`, `/.git/config`, `/wp-login.php`), entries added to `.gitignore`.
- [ X ] Decoy-route hits: low severity, counted per IP per window; never 403 on route hits alone. Canary credential use: critical.

### 19.6 Attack response
- [ X ] Threat score per IP/user; log → challenge (429) → temporary block → alert. Auto-block off unless `threatAutoBlock: true`; `threatMaxBlockMs` default 15 min. Shared-IP/NAT risk documented.
- [ X ] An optional Redis store may share that block list across processes. Redis is an optional peer, lazy-loaded, never a hard dependency (R13). The default store stays in memory.

---

## 20. Frontier: Supply-Chain Defense [experimental]
- [ X ] Static only; never executes or installs analyzed packages. Registry host locked to `registry.npmjs.org`.
- [ X ] Malicious heuristics: install scripts, obfuscation, reads of `~/.npmrc`/`~/.ssh`/env combined with network calls (`SUPPLY-NPMRC-NET-001`), install scripts (`SUPPLY-INSTALLSCRIPT-001`).
- [ X ] Version diffing → `SUPPLY-BEHAVIOR-001` on newly added scripts/network/child_process.
- [ X ] Release cooldown (`deps.minReleaseAgeHours: 72`), provenance-drop detection, dependency confusion, maintainer change, lockfile non-registry URLs / altered integrity.
- [ X ] `fullshield install <pkg>` wraps `npm install --ignore-scripts` + checks.
- [ X ] Phase 31: `SUPPLY-WORM-001` (token read + publish/registry PUT/GitHub repo or workflow creation), `SUPPLY-WORKFLOW-001` (writes to `.github/`, `.git/hooks/`, CI config), provenance coverage score (unknown ≠ present), VEX output.

---

## 21. Frontier: Exploit Confirmation & Fuzzing [experimental, local only]
- [ X ] Scope lock: `localhost`, `127.0.0.1`, or a container FullShield started. Refuses public names, IPv6, encoded IPv4 forms, metadata, `127.0.0.2`; raw authority checked.
- [ X ] Route inventory from Express/Fastify (and Next/Nest/Hono/Koa behind flag) and OpenAPI.
- [ X ] Harmless canaries only (marker `UNION SELECT`, `echo` token, planted canary file). Destructive payloads (`DROP`, `rm`, `dd`) rejected.
- [ X ] Runtime-assisted confirmation via sink hooks in monitor mode. Property-based fuzzing (fast-check). IDOR confirmation with two configured test users.
- [ X ] Findings get `status` and a reproducible `curl` proof against localhost.

---

## 22. Frontier: Platform & Intelligence [experimental]

### 22.1 MCP server
- [ X ] `fullshield mcp --stdio` (official `@modelcontextprotocol/sdk`, optional peer). Tools: `scan`, `get_findings`, `explain_finding`, `propose_fix` (diff, `wrote: false`), `verify_fix` (temp copy). Read-only.

### 22.2 LLM-app security
- [ X ] `LLM-001` input concatenated into system prompts; `LLM-002` model output → sink; `LLM-003` dangerous tool without confirmation; `LLM-004` key in client bundle; `LLM-005` no output/token limit. Mapped to OWASP Top 10 for LLM Applications.

### 22.3 Threat model
- [ X ] `threat-model`: routes, auth middleware, stores, external calls, secrets → STRIDE table + Mermaid.

### 22.4 Incremental & monorepo
- [ X ] `scan --changed` / `--since <ref>` (fail-closed without flag); workspaces; persistent cache; targets in Phase 42.

### 22.5 Local dashboard & history
- [ X ] `report --serve` binds 127.0.0.1 only, rejects other Host headers, `/api/ingest` GET → 405. History in `.fullshield/history.db` (node:sqlite, lazy). Every DB handle closed in try/finally (Windows).

### 22.6 Compliance mapping
- [ X ] Every rule ID maps to OWASP Top 10, CWE, ASVS, PCI DSS (test fails on a missing row). `report --compliance pci` prints "This is not a certification or audit."

### 22.7 IaC (light)
- [ X ] GitHub Actions (unpinned actions, `pull_request_target`, write-all permissions, secrets in logs), Terraform (public S3, `0.0.0.0/0` on 22/3306/5432, unencrypted storage), Kubernetes (privileged, hostNetwork), compose (privileged). ~20 rules max.

### 22.8 Remediation agent
- [ X ] `agent --max-prs N`: safe rule-based fixes only, ≤ N files per PR, project tests run, PR via localhost API only (refuses api.github.com and non-loopback), pushes only `fullshield/agent-*` branches to a local bare remote, never merges, never pushes `main`/`master`/`develop`, stops on first test failure. CRLF/Windows-safe git.

---

## 23. Benchmark & Proof
- [ X ] Suites: tuning apps (B2), untouched holdouts (B3), real-world corpus (Phase 41), own fixtures and RASP corpora.
- [ X ] Publish per release: recall per class (labeled), precision (labeled), scan time, runtime overhead p50/p95/p99, RASP block rate on attack corpus, benign block rate.
- [ X ] Known-misses list with one-line reason each.
- [ X ] Regression gate: CI fails if any benchmark metric regresses > 2% vs last release (after Phase 37).
- [ X ] Self-authored corpus numbers are always labeled self-authored.

---

## 24. Scope Tiers & Phase Map

| Tier | Phases | Status |
|---|---|---|
| Core | 1–10 | done, stable |
| Pro | 11–16 | done; watch/edge/reachability/SBOM stable, AI experimental |
| Frontier | 17–24 | done, experimental |
| Next | 25–35 | done; 25 and 26 bench + 26b/26c/NoSQL fixes affect stable, 27–35 experimental |
| Depth | 36–45 | shipped in 0.2.0 (Section 29 is reference) |
| Impact | 46–59 | [X] 46–49 and 53. 50–52 and 54–59 are not finished. |
| Advanced | 60–75 | [X] 61, 64, 66, 74. 60, 62, 63, 65, and 70 are started and still have open items. |
| npm depth | 108–250 | specified in Section 47; part of the 1.2.0 scope; not started |

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

### [X] Phase 25 — Windows + lazy SQLite (shipped in 0.1.1)
Windows × Node 22/24 in CI; quoted-filename test `skipIf(win32)`; idempotent `HistoryDb.close()` in try/finally; CRLF-independent fixer/agent diffs restoring original EOL; POSIX pathspecs; `--import` via `pathToFileURL`; runtime entries don't import `node:sqlite`; LRU flood test asserts retained-heap delta < 10 MB plus exact LRU sizes.

### [X] Phase 26 — Public benchmark harness
`bench:public` clones pinned NodeGoat, Juice Shop, DVNA; ground truth from official docs (`reviewed: false`, in/out-of-scope); triage files; BENCHMARK.md; non-blocking CI `bench` job.

### [X] Phase 26b — Stable public-bench misses (stable-output change)
Mongo `$where`; destructured `{ query }` taint; `md5(tainted)`; `autoescape: false`; helmet line attribution (not counted as recall); `CONFIG-DIRLIST-001`; `SECRET-SESSION-001`.

### [X] Phase 26c — Engine gaps from goof holdout (stable-output change)
Receiver taint through method calls; taint through function params (5 hops); zip-slip sinks + `req.files` source; manifest-line attribution for direct deps. goof and vulnerable-node are now `seen`.

### NoSQL (stable-output change, human-approved)
`SAST-NOSQLI-001` flags request input as Mongo filter value unless coerced/validated/sanitized; Mongo/mongoose receivers only.

### [X] Phase 27 — SAST/RASP coverage gaps [`FULLSHIELD_EXPERIMENTAL_SAST_GAPS`]
Numeric SQL positions; ORM raw sinks (Prisma `$queryRawUnsafe`/`$executeRawUnsafe`/`Prisma.raw` — not `$queryRaw` tagged; Sequelize `query`/`literal`; Knex `raw`/`whereRaw`/`orderByRaw`; TypeORM `query`/`createQueryBuilder().where(concat)`; Drizzle `sql.raw`); template-literal shell (`spawn('sh', ['-c'])`, execa `shell: true`, zx `$.raw`/`{ quote: false }`). ≥ 10 attack cases per context, benign 0.

### [X] Phase 28 — Frameworks [`FULLSHIELD_EXPERIMENTAL_FRAMEWORKS`]
Next.js (route handlers, Server Actions, Pages API), NestJS (`@Body/@Query/@Param/@Headers`, `@UseGuards`), Hono, Koa sources and auth patterns; `fullshield/runtime/koa`, `/hono` (optional peers).

### [X] Phase 29 — New classes [`FULLSHIELD_EXPERIMENTAL_CLASSES`]
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

### [X] Phase 30 — Secrets advanced [`FULLSHIELD_EXPERIMENTAL_SECRETS_ADV`]
`--history` (streamed `git log -p`, blob-hash dedupe, `introducedIn`, `stillAtHead`); `--bundle <dir>` (`dist/`, `.next/static`, `build/`, `NEXT_PUBLIC_*`/`VITE_*`); `--verify-secrets` + `--i-own-these-credentials` (AWS STS GetCallerIdentity, GitHub GET /user, Stripe GET /v1/balance, Slack auth.test; `live|revoked|unknown`; never logs the key; never in CI templates).

### [X] Phase 31 — Supply chain advanced + VEX [`FULLSHIELD_EXPERIMENTAL_VEX`]
Worm and workflow-tampering indicators; transitive overrides written to `package.json` (lockfile never edited); provenance coverage score; `fullshield vex --format openvex|cyclonedx` (`not_affected` only when `not-imported`; else `under_investigation`).

### [X] Phase 32 — Response DLP [`FULLSHIELD_EXPERIMENTAL_DLP`]
`shieldGuard({ dlp: { mode: 'monitor'|'mask'|'block' } })`: responses ≤ 64 KB scanned for secrets, stack traces, internal IPs/hostnames, Luhn card numbers, bulk emails on single-email routes; < 1 ms p95; streaming bodies not inspected.

### [X] Phase 33 — MCP config security [`FULLSHIELD_EXPERIMENTAL_MCPCFG`]
`.cursor/mcp.json`, `.vscode/mcp.json`, `.mcp.json`, Claude Desktop config (home only with `--include-home`). `MCP-001` inline secrets (high), `MCP-002` unpinned npx/@latest (medium), `MCP-003` shell/unrestricted fs-write without allowlist (medium), `MCP-004` tool-description injection (high), `MCP-005` remote over http (medium). Model-provided tool args are taint sources. `guardTools` opt-in library.

### [X] Phase 34 — Policy-as-code + PR summary [`FULLSHIELD_EXPERIMENTAL_POLICY`]
`fullshield.policy.json`: required modules, severity overrides, `failOn` per branch, exceptions requiring `owner`, `reason`, ISO `expires` (missing → exit 2; expired → CI fails, finding not hidden). zod is an optional peer. `scan --pr-summary` deterministic Markdown, golden-file tests.

### [X] Phase 35 — Host SSH exposure [`FULLSHIELD_EXPERIMENTAL_HOST`]
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
- [ X ] `SAST-COOKIE-001` must not duplicate `SECRET-SESSION-001` (test: exactly one finding with `--experimental-classes`).
- [ X ] `SAST-CSRF-001` library + app-level middleware recognition (negative test: middleware in app.js, routes in router file).
- [ X ] NoSQL PascalCase heuristic: negative test for TypeORM `BaseEntity` `User.find(...)` without a direct typeorm import.
- [ X ] Juice Shop `data/static/codefixes/*` produce 6 NoSQL hits (challenge copies) — documented, no special-case exclusion.
- [ X ] 0.1.3 missing provenance — root cause + gate.
- [ X ] npm packument README empty under staged publishing (npm/cli#9405) — documented in RELEASING.md; no publish-flow workaround.

---

## 28. Known Limitations (mirror in README; update every release)
- [ X ] 1.0.0 freezes the stable contract in `docs/stability.md`. Experimental flags are not part of that promise.
- [  ] Phase 87 provenance signals are informational (`SUPPLY-PROV-001`, medium). They never mean a package is malicious. Offline or cache-miss data stays unknown.
- [ X ] The package enforces Node ≥ 22.13 in `engines`, `doctor`, and CI (Node 22 and 24). Node 20 reached end of life in April 2026. The README says 1.0.0 and does not claim a reviewed recall number. History storage may still say it needs `node:sqlite`. That API is inside the floor. Branch protection job names are a human GitHub setting after the new jobs report once.
- [  ] Ground truth is unreviewed (`"reviewed": false` on every bench app). Cursor does not flip that flag. A human reviews answer keys. Blank label, reviewer, and note cells stay blank.
- [ X ] Default console prints the Phase 47 shown rows only (human decision 2026-10-18). JSON stays the full list. D4 accepts the 2026-10-18 grouped-row recount: NodeGoat 36, goof 63, juice-shop 49, dvna 14, vulnerable-node 41. There is no row-count threshold. Ground truth stays unreviewed.
- [  ] Platforms: Linux, macOS, Windows on Node ≥ 22.13.
- [  ] Benchmark recall figures are on **unreviewed** ground truth; tuning-app figures are `seen` (rules were fixed against them). Current untouched-app figure: none (all apps used). Do not cite a recall percentage until Phase 37 + review.
- [  ] RASP corpus results are on self-authored/vendored corpora.
- [  ] NoSQL: a filter object or array built from request input and passed into find/update is reported, including a helper in the same file, a nested function that closes over the filter, and a SQL string or Mongo filter returned from another file (Phase 51). Nested closures and some dynamic dispatch are still missed.
- [  ] Template engines: Swig `{{ name }}` is `SAST-XSS-001` when the view engine is Swig and the name is tainted. `{{csrftoken}}` and unrendered templates are not findings. Handlebars `{{ }}` stays unflagged. JSON-context XSS, `url.includes` allowlist bypass, and the DVNA calc vs `err.stack` pattern stay missed.
- [  ] Reachability is import-level + any-call; symbol-level only after Phase 39.
- [  ] All features from Phase 27 onward, RASP, AI, and Frontier are experimental.
- [  ] Capability profiles (Phase 86, `FULLSHIELD_EXPERIMENTAL_CAPABILITIES`) read installed files only and do not run install scripts. `deps-diff` reports a new capability only when the previous integrity is already cached. Files over 1 MB are skipped. Comments and strings that mention an API can match.
- [  ] FullShield does not stop attacks by itself: `--fail-on` and runtime monitor/block are the prevention mechanisms.
- [  ] No deterministic detection of business-logic or authorization bugs.
- [  ] Production reliance is Section 38. README and release notes keep that stance. Do not claim FullShield replaces Semgrep, npm audit, OSV-Scanner, or a secrets scanner.
- [  ] `ingest` (Phase 83) reads local report files only. It does not run Semgrep, npm audit, or OSV-Scanner and does not fetch. It does not set `fullshieldPriority` (Phase 84; KEV/EPSS stay blocked on Phase 56). An npm audit file with no installed version uses `unknown` and will not match an OSV-Scanner row that has a version.
- [  ] Phase 91 fix verification re-scans the patched file and its direct importers only. A missing OSV cache file for the planned version is `does-not-remove`. It does not run project tests or `npm install`.
- [  ] Default `scan` npm coverage is lockfile `name@version`, an OSV query, import-level reachability, and a Levenshtein-1 typosquat check on direct dependencies. Non-registry resolved URLs, missing integrity, release cooldown, and install-script heuristics live in the supply helpers (`fullshield install`), not in default `scan`. Nested copies of one package name share one edge set. Tarball bytes are not checked against `dist.integrity`. Phases 108–250 (Section 47) are in the 1.2.0 scope and are not built yet.

---

## 29. Depth Phases 36–45 (SHIPPED in 0.2.0 — reference)

Do not rebuild these. `0.3.0` grouped duplicate finding keys. `0.4.0` reports a Mongo filter built in the same function. Neither version is a reason to reopen 36–45. The next work is Section 36, which orders Section 32 and Section 37.

### [X] Phase 36 — Release integrity (BLOCKS ALL RELEASES)
Build:
1. Provenance gate in `publish.yml` (1.4). Root-cause 0.1.3's missing attestation; document in RELEASING.md.
2. `scripts/default-scan-diff.mjs`: snapshots default-scan findings per target into `bench/snapshots/<version>.json`; diff mode prints added/removed/changed `(ruleId, file, line, severity)`; exit 1 on any diff unless `--approved <file>` matches exactly. Create snapshots for 0.1.1 and 0.1.3 from their published tarballs (`npm pack fullshield@X` into temp, run that CLI).
3. `scripts/semver-check.mjs`: HEAD vs last tag — new rule IDs, commands, flags, exports, or stable-output diff → minor required; else patch. Fails if the `package.json` bump is smaller than required.
4. `scripts/pack-budget.mjs`: fails if unpacked > 3.0 MB, files > 320, or hard `dependencies` added vs last tag; prints what grew.
5. Section 27 items.
6. CHANGELOG `0.2.0` draft: every stable-output change since 0.1.1 (from default-scan-diff 0.1.1 → HEAD) under the R10 heading, plus every experimental feature with its flag.

Acceptance: unit tests for all four scripts; `npm publish --dry-run` in a test job (never a real publish); default-scan-diff 0.1.3 → HEAD empty or human-approved; semver-check says `minor`; pack-budget passes. **No tag.** Human releases 0.2.0 via Section 2.

### [X] Phase 37 — Benchmark governance
Build:
1. `bench/holdouts.json` (B1) for all current apps with correct status.
2. Three new untouched holdouts (intentionally vulnerable Node/TS apps not used before; pinned SHAs; ground truth from their docs, cited, `reviewed: false`). **Do not scan them** in this phase. `status: "untouched"`, `firstRunDate: null`.
3. `bench/REVIEW.md` checklist (source link opens, line matches, class correct, scope correct) + `bench/review-sheet.mjs` exporting each app's ground truth as a Markdown table for the human.
4. `bench/sample-triage.mjs --app X --n 20`: random unmatched findings for human labeling → `bench/<app>/human-triage.json` → used for reviewed precision.
5. BENCHMARK.md regenerated with B2–B7 labels.

Acceptance: zod schema test for holdouts.json; test asserts no scan result file exists for untouched apps; review sheets generated.

### [X] Phase 38 — Competitive benchmark (honest)
Build:
1. `bench/compare.mjs` on **tuning** apps only: FullShield default scan, Semgrep Community Edition with public rulesets (`p/javascript`, `p/typescript`, `p/nodejs`), OSV-Scanner, `npm audit --json`. Local tools only, no accounts. Pinned versions.
2. Documented mapping table from each tool's findings to B4 classes; unmapped counted separately.
3. `COMPARISON.md`: per app, per class — TP/miss against the same ground truth, total findings; for deps, total alerts vs FullShield reachable + via-dependency.
4. Neutral wording; report losses; no claims about tools not run.

Acceptance: reproducible with pinned versions; non-blocking CI job; human reviews mapping before COMPARISON.md is linked anywhere.

### [X] Phase 39 — Reachability v2 (headline)
Build:
1. Symbol-level reachability when advisory data names affected functions/exports. Resolve named imports, `require('x').fn`, subpaths (`lodash/merge`), default/namespace member calls, re-export barrels. Classes `symbol-reachable` / `symbol-not-called`.
2. No symbol data → keep import-level classes. Never guess symbols.
3. For `reachable-via-dependency`: if `node_modules` exists, statically parse the direct dependency to check whether it calls the vulnerable export; else `unknown`. Never execute.
4. TS `paths`/`baseUrl` and package `exports` maps in resolution (shared resolver with Phase 40).
5. BENCHMARK.md: alert count before/after per tuning app, and every downgraded finding listed with evidence.

Acceptance: fixtures per import style/alias/subpath/barrel; `symbol-not-called` never applied without advisory symbol data (test); `DEPS-MALICIOUS-001` never downgraded (test). Stable-output change → R10.

### [X] Phase 40 — Taint engine v2 [`FULLSHIELD_EXPERIMENTAL_TAINT_V2`]
Build propagation for: async/await and promise chains; callbacks and array methods; `call/apply/bind`; destructuring, spread, `Object.assign`, nested property paths; class fields / `this.x` across methods; closures; cross-file through aliases and barrels. Depth 5, content-hash cache, time budget test (Phase 42).

Acceptance: positive + negative generic fixture per propagation kind (written from scratch, B8); tuning recall reported `seen`; untouched apps not run.

### [X] Phase 41 — Precision pass
Build:
1. `bench/realworld.json`: 10 popular maintained non-vulnerable Node/TS repos (Express, Fastify, Nest, Next, Koa mix), pinned SHAs.
2. `bench/fp-scan.mjs`: default scan + each experimental flag separately; export findings for triage.
3. Budget per stable rule: ≤ 1 false positive per 10k LOC (human-sampled, B6). Over budget → narrow with negative test, downgrade confidence, or move behind a flag (R10 if stable).
4. Per-rule precision table in BENCHMARK.md.

Acceptance: every stable rule has a precision row; every over-budget rule has a human-approved decision.

### [X] Phase 42 — Performance
Build:
1. Harness on 3 real repos ≥ 50k LOC (pinned): cold, warm-cache, `--changed`.
2. Targets on ubuntu-24.04 runner: cold ≤ 60 s, warm ≤ 20 s, incremental ≤ 5 s, peak memory ≤ 1.5 GB.
3. Worker-thread parse pool (CPUs − 1, configurable); parse cache keyed by content hash + FullShield version.
4. CI fails if p50 of 3 runs regresses > 15% vs stored baseline.

Acceptance: targets met or documented with numbers in Known Limitations; identical output with/without workers (test).

### [X] Phase 43 — Experimental → stable promotion
Criteria (all required, per feature):
- [ X ] SAST: recall gain on ≥ 1 untouched app with reviewed ground truth, and within Phase 41 FP budget.
- [ X ] Runtime: p95 ≤ 1 ms overhead, 0 benign blocks on corpus.
- [ X ] Others: phase acceptance + 0 crashes on the Phase 41 corpus.
- [ X ] Docs page, CHANGELOG entry, migration note, human approval.

Build `scripts/promotion-report.mjs` listing each flag's met/unmet criteria with evidence. Promote only approved features; each promotion is an R10 change; promoted flags become no-ops with a deprecation notice for one minor release.

### [X] Phase 44 — Developer experience
Build:
1. Console output: by severity, top 10 first, "N more — use --json"; each finding file:line, one-line why, one-line fix, rule doc link.
2. `fullshield doctor`: Node version, lockfile type, cache state, flags, config validity, OSV reachability (respects `--offline`).
3. Error codes `FS-E###` with fix hint and docs link; no raw stack traces without `--debug` (test).
4. README rewrite: quickstart, stable findings, non-goals, experimental list, benchmark and comparison links (after Phase 38 review), no superlatives (4.4).
5. `docs/demo.md` from a real run (no fabricated output).

Acceptance: console snapshot tests; doctor tests per check; README link-check test.

### [X] Phase 45 — Self-security hardening
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
| Repo `package.json` | 1.2.0. npm still serves 1.0.1, published 2026-10-21T02:43:27Z with provenance. Tag `v1.0.1` is `dc2b719` on `main`. |
| `engines` | `>=22.13` in package.json, doctor, and CI (Node 22 and 24). `main` requires the six checks in `docs/branch-protection.md`. |
| Built | Phases 1–55 and 57–94 are in this tree. Phase 56 is not (R15). Phase 65 is coded; the 5-second nest and undici target is unmet. |
| Today's queue | Section 45 autopilot run for 1.2.0. Scope order: 105 → 95 → 96 → 102 → 104 → 97 → 99 → 100 → 98 → 103 → 101 → 106 → 107, then 108 through 250 (Section 47). Experimental only (R11). No promotion. One version, `1.2.0`. |
| Phases 76–93 | in this tree, behind their experimental flags |
| Precision | Phase 76 writes null labels. No reviewed precision rate is published. |
| Phase 56 | blocked on R15 amendment (EPSS/KEV hosts) |
| Ground truth reviewed | none (all `reviewed: false`). Human only |
| Untouched holdouts in reserve | 3 (verademo-javascript, serverless-goat, mongection), not scanned |
| Provenance gate | in publish.yml. `1.0.1` published with provenance. `0.1.3` was published without provenance and must not be repeated |
| Section 27 open items | COOKIE/CSRF already covered; BaseEntity negative test added; Juice Shop codefixes documented |
| Comparison / precision / promotion | comparison run in COMPARISON.md; precision not sampled; nothing promoted |
| Human decisions 2026-10-18 | D1: doctor test treats Node 20.11 as too old (Phase 46). D2: console-cap test expects 20 rows (Phase 47). D3: Phase 47 shown rule replaced; see Phase 47 and 47.1. D4: the 2026-10-18 grouped-row counts are accepted and the 40-row stop is removed. D6: published 0.3.0 is approved and is not a stop; git must match it. D7: restoring that source onto next is an approved R10 change only if the R1 proofs pass. D8: the restore commit was 0.3.0. On 2026-10-18 the human set 0.4.0 and asked to publish it. |
| Noise | NodeGoat JSON stays 256. D4 accepts the 2026-10-18 grouped-row recount (nodegoat 36, goof 63, juice-shop 49, dvna 14, vulnerable-node 41). No row-count threshold. Rule unchanged. |

---

## 31. Explicitly Rejected (do not build)
- [ X ] Container image / OS package scanning (use Trivy/Grype).
- [ X ] Host intrusion prevention, firewall management, OS-level IP blocking (use fail2ban, CrowdSec, cloud WAF).
- [ X ] Scanning or attacking non-local hosts.
- [ X ] Cyber-physical / hardware-implant detection.
- [ X ] An LLM in the request path.
- [ X ] Telemetry of any kind.
- [ X ] Anything that auto-merges, auto-deploys, deletes code, edits lockfiles by hand, or publishes without human approval.
- [ X ] A VS Code extension. The MCP server is the editor integration.
- [ X ] A pull-request comment bot. `scan --pr-summary` prints Markdown. Phase 59's Action uploads SARIF. Neither posts a comment.
- [ X ] A new detection category before Phase 47's console acceptance passes. Phases 50 and later wait.
- [ X ] Hiding `DEPS-VULN-001` or lowering its severity to shrink the NodeGoat count. Phase 47 folds the console view. The JSON list stays complete.
- [ X ] Bundling, mirroring, or downloading third-party rule registries (Semgrep registry or others). Phase 90 reads user-supplied files only.
- [ X ] Running the project's tests or app to verify a fix (R15). Phase 91 verifies by re-scanning only.
- [ X ] Marketing words in any shipped file: "number 1", "best", "leader", "one of a kind", "complete protection", "prevents attacks", "full shield from cyber attacks".
- [ X ] ML-based scoring. Phase 84 is a documented, deterministic table.

---

## 32. Impact Phases 46–59 (NEXT)

Build 46 and 47 first. 47 is the product change. 46 is the runtime and version correction that ships in that same release. Do not start 48 until 47's acceptance passes. Do not start 50 or any later detection phase before 47. Write the failing test first (R4). `clean-app` stays at 0 findings (R12). Do not edit `ground-truth.json`, `triage.json`, or `expected-findings.json` (R3). Do not set `"reviewed": true`.

`scan --json` finding keys stay `(ruleId, file, line, severity)` unless a phase below says the key set changes. A key-set change is R10: human approval before merge, CHANGELOG heading **"New/changed stable findings — may change CI results; use --update-baseline"**, `bench/snapshots/HEAD.json`, `bench/snapshots/DIFF.txt`, and a minor bump (R16).

### [X] Phase 46 — Supported runtime and README version
Node 20 reached end of life in April 2026. This spec's runtime is Node ≥ 22.13. The package is still `engines: ">=20.11"`. The README already says 0.4.0 and says the engines field has not moved yet.

Build:
1. `package.json` `engines` is `>=22.13`. `doctor` uses that same floor.
2. CI runs Node 22 and 24 only. Drop Node 20 from the matrix and from the required-check names in the same change, after the new jobs have reported once.
3. README, `docs/NODE-20.md`, and any other supported-runtime sentence name Node ≥ 22.13 as the floor the package enforces, not as a future phase. History storage may still say it needs `node:sqlite`. That API is inside the floor.
4. A test reads `package.json` `version` and the README version and fails on a mismatch. The rewrite does not add a recall or precision claim.

Acceptance: the engines test fails if the floor is below 22.13; the version test fails if the README and `package.json` disagree; `npm run verify` passes on Node 22 and 24. No new rule, flag, or finding.

### [X] Phase 47 — Actionable console view
Default human output shows the rows a developer can act on. Nothing is removed from the result.

**Shown rule replaced by human decision 2026-10-18 (D3).** A finding is **shown** when any of these is true:

- [x] `ruleId` is `DEPS-MALICIOUS-001` (later also `SUPPLY-SECHOLDER-001` and `SUPPLY-STEALER-001`).
- [x] `ruleId` is `DEPS-VULN-001`, and `reachability` is `reachable`, `symbol-reachable`, `reachable-via-dependency`, or `reachability-unknown`, and the finding is not dev-only.
- [x] `module` is `sast`, `secrets`, or `config`, and (severity is `high` or `critical`, or confidence is `high`).

Everything else is **folded**. That includes `not-imported`, `imported-not-called`, dev-only, `DEPS-DEPRECATED-001`, `DEPS-NOLOCK-001`, and `DEPS-TYPOSQUAT-001` unless the sast/secrets/config rule matches. Severity and confidence never decide whether a dependency row is shown. Only reachability does, plus the malicious rule above.

Console grouping (console only, human decision 2026-10-18):

- [x] Shown dependency findings print one row per package name. Each row lists every installed version, the advisory count, the highest severity, the best reachability class, the first dependency path, and the first import line.
- [x] The 20-row cap and `N more actionable — use --json` count grouped rows.
- [x] The folded line counts findings, not rows: `M more (not directly reachable, or below high confidence) — --all or see JSON`.
- [x] `--all` prints every finding, with no 20-row cap.
- [x] JSON, SARIF, Markdown, HTML, the baseline, and `--fail-on` stay the full finding list. A test proves those reporters are not grouped.

Order of shown rows (human decision 2026-10-18): `DEPS-MALICIOUS-001` first; then severity, highest first; then reachability `reachable` / `symbol-reachable`, then `reachable-via-dependency`, then `reachability-unknown`, then findings with no reachability field; then file, line, ruleId. Console only. `sortFindings` for other reporters is unchanged.

Also see **47.1**. Both are part of this acceptance.

Acceptance (human decision 2026-10-18 (D4)): the shown rule from D3 passes its tests, and the per-app table is recorded in CHANGELOG under Unreleased and in the Phase 47 report. There is no row-count threshold. The shown rule, the 20-row cap, and severities stay as D3 left them.

A not-imported `DEPS-VULN-001` is folded even when its severity is high. A `reachable-via-dependency` advisory for the same package name groups with a second advisory into one row. A malicious advisory is shown. A high SAST hit is shown. A low-confidence SAST hit is folded. Dev-only and typosquat rows are folded. `--fail-on high` still exits 1 when a folded finding is high. JSON still lists every finding. `clean-app` console has no finding rows.

### [X] Phase 48 — Unused dependency removal
State, for direct `dependencies` that no project file imports and that are not required by an imported package: how many packages that is, and how many advisories sit only on those packages. Example shape: `12 packages are never imported; removing them clears 41 advisories.`

- [x] Imported and `imported-not-called` packages are not in the list.
- [x] `fix --unsafe` may delete those names from `package.json`. It does not edit the lockfile. It prints `run npm install`.
- [x] The scan finding list does not lose those advisories.
- [x] `DEPS-MALICIOUS-001` on an unused direct package is included in the offer. It is still never downgraded.

Acceptance: positive fixture (unused direct dep with a cached advisory) and negative fixture (imported dep, and a dep that is imported but not called). `fix` without `--unsafe` prints the plan and writes nothing. JSON finding keys are unchanged.

### [X] Phase 49 — Upgrade plan
Choose the smallest set of direct version bumps that clears the most advisories. Use only versions present in the OSV `affected` ranges in the cache. If OSV names no fixed version, say so and do not invent one.

Example shape: `1 bump (express 4.17 → 4.21) resolves 9 findings.`

Ties break by fewer bumps, then by package name. A same-major bump is a safe fix. A major bump is `--unsafe`. Offline mode uses the cache only.

Acceptance: a fixture lockfile and a fixture OSV cache produce one deterministic plan. A second fixture with no fixed version produces no bump. The plan does not change `(ruleId, file, line, severity)` keys.

### Phase 50 — Template-engine-aware XSS
Read `app.set('view engine', ...)` and `app.engine(...)`. Flag `{{ }}` in a template only when that engine is on the raw-mustache list. The list starts with Swig. Adding an engine requires a new positive fixture and a new negative fixture.

- [x] The engine is unknown: do not flag `{{ }}`. That is the current `.html` behavior.
- [x] Handlebars / `hbs`: `{{ name }}` is a negative fixture.
- [x] Swig, with the view engine set to Swig: `{{ name }}` is a positive fixture for `SAST-XSS-001`.
- [x] Existing `<%-` and `{{{` checks stay as they are.

This changes default `scan --json` on apps that set Swig. R10 applies. Do not edit ground truth. Do not claim a NodeGoat recall change.

Acceptance: the Swig positive fixture fails before the implementation and passes after. The Handlebars negative fixture reports no `SAST-XSS-001`. `clean-app` stays at 0. Snapshot diff is written and waits for human approval before merge.

### Phase 51 — Cross-file returns
Follow a SQL string or a Mongo filter built in one file and returned to a caller in another file, up to the existing depth of 5. One finding, with a `trace` that includes both files. The same path already works for a helper in the same file. This phase is the other file.

- [x] Negative fixture: the helper returns a literal.
- [x] Do not turn on `FULLSHIELD_EXPERIMENTAL_TAINT_V2`.
- [x] Fixtures are written from scratch (B8).

R10 applies when a bench app gains or loses a key. Do not edit ground truth.

Acceptance: SQL and NoSQL each have a cross-file positive and a literal-return negative. Same-file cases already covered stay covered. `clean-app` stays at 0.

### Phase 52 — Phantom and mismatched dependencies
- [x] `DEPS-PHANTOM-001`: a package import that is not in `dependencies`, `devDependencies`, `optionalDependencies`, or `peerDependencies`. Node built-ins and relative imports are not packages.
- [x] `DEPS-LOCKMISMATCH-001`: a `package.json` range the locked version does not satisfy. Use the existing semver helper. Do not guess a version.

New rule IDs change stable output. R10 applies. Positive and negative fixtures for each rule. `clean-app` stays at 0.

### [X] Phase 53 — Validation inference [`FULLSHIELD_EXPERIMENTAL_VALIDATION`]
Off unless `FULLSHIELD_EXPERIMENTAL_VALIDATION=1` or `scan --experimental-validation`.

Detect a zod, joi, or class-validator schema attached to a route. Clear taint only for the class that schema constrains. A schema that forces a string, number, or boolean can clear a NoSQL operator-injection finding on that field. A `z.string()` does not clear SQL string concatenation. An unvalidated field on the same route still reports.

Default `scan --json` is unchanged until the human approves an R10 diff and promotes the flag (Phase 43).

Acceptance: positive (schema covers the field, flag on, NoSQL finding absent), negative (SQL concat of a validated string still reports; flag off, the NoSQL finding remains). `clean-app` stays at 0 with and without the flag.

### [X] Phase 54 — Per-workspace lockfiles [`FULLSHIELD_EXPERIMENTAL_WORKSPACES`]
Off unless `FULLSHIELD_EXPERIMENTAL_WORKSPACES=1` or `scan --experimental-workspaces`.

npm, pnpm, and yarn workspaces: scan each workspace with its own lockfile when that file exists, and attribute findings to that workspace package. The root package still uses the root lockfile. A repo with one package scans as it does today, flag on or off.

No new hard dependency. Default `scan --json` of a single-package app is unchanged.

Acceptance: a two-workspace fixture reports an advisory on the workspace that locks the vulnerable version, and does not report it on the workspace that does not. The single-package fixture matches the unflagged scan.

### [X] Phase 55 — Runtime-observed reachability [`FULLSHIELD_EXPERIMENTAL_OBSERVED_REACH`]
Opt-in and local. The register hook, when `FULLSHIELD_EXPERIMENTAL_OBSERVED_REACH=1`, appends loaded package names and export names to `.fullshield/observed-reach.json` in the project directory. The file is never sent anywhere. A hook error fails open and the app keeps running.

The next scan reads that file only when the same flag is set. It may confirm a package as reached, or record a downgrade, from names in the file. Default `scan` ignores the file, so `(ruleId, file, line, severity)` does not change. A missing or unreadable file changes nothing.

This is not telemetry. Acceptance includes a test that the hook performs no network call.

### Phase 56 — Exploit prioritization [`FULLSHIELD_EXPERIMENTAL_EXPLOIT_INTEL`]
**Do not start.** R15 allows OSV, `registry.npmjs.org`, user-configured webhooks and AI providers, and localhost. EPSS and the CISA Known Exploited Vulnerabilities catalog are not on that list. Starting this phase requires the human to amend R15, in the same message that says to build it, naming the hosts.

When that amendment exists:
- [  ] EPSS from FIRST and the KEV flag from CISA. Cache them the way OSV results are cached. `--offline` uses the cache only. A missing cache leaves the fields unset. Never invent a score.
- [  ] Fields sit on the dependency finding. They do not change severity. `DEPS-MALICIOUS-001` stays critical.
- [  ] With the flag on, the Phase 47 console sorts known-exploited reachable findings first.
- [  ] With the flag off, `scan --json` keys are unchanged.

### [X] Phase 57 — Custom rules [`FULLSHIELD_EXPERIMENTAL_CUSTOM_RULES`]
Off unless `FULLSHIELD_EXPERIMENTAL_CUSTOM_RULES=1` and a rules file is configured. A rules file with the flag off is not loaded.

The file is a schema of `id`, `severity`, `sources`, `sinks`, and `message`. It cannot contain JavaScript. A rule that fails the schema is rejected with an `FS-E` code and is not run. No new hard dependency. A YAML parser, if one is required, is an optional peer, lazy-loaded, with an install hint.

Acceptance: one shipped fixture rule has a positive and a negative test. An invalid file fails closed. Default scan with no flag matches the scan from before this phase.

### [X] Phase 58 — Route security map [`FULLSHIELD_EXPERIMENTAL_ROUTES`]
`fullshield routes` refuses to run unless `FULLSHIELD_EXPERIMENTAL_ROUTES=1` or `--experimental-routes`.

Print a table of method, path, auth middleware, validation, and the sink classes that route can reach (SQL, shell, file system, and the other sinks the SAST rules already name). The table does not detect IDOR or missing ownership checks. The command makes no network call. The README states that limit in the same change.

Acceptance: a fixture app with one authenticated route and one unauthenticated sink route produces both rows. `clean-app` is not given a new default-scan finding.

### [X] Phase 59 — GitHub Action wrapper
Extend the generated workflow and add `templates/action/` so it can be published as `kathanp/fullshield-action`. The Action runs the scan, uploads SARIF, and caches the baseline. It pins the `fullshield` version. It does not post a pull-request comment and it does not phone home.

Publishing the Marketplace listing is a human action (R1). This phase stops at the files in this repo.

Acceptance: the template is valid workflow YAML; a test asserts SARIF upload and baseline-cache steps exist; the Action manifest names no telemetry endpoint.

---

## 33. Carried from the 2026-10-14 spec

That draft was deleted. These items were in it and were only shortened here. They are now stated in full above or in the section named.

- [ X ] Runtime bundle under 50 KB and no parser imports (Section 16).
- [ X ] `validator.*` clears taint only for the check that function performs (Section 6.2).
- [ X ] Optional Redis store for the in-memory threat block list, as an optional peer (Section 19.6).
- [ X ] Optional batch `ai summarize` for anomaly events, off the request path (Section 18.4).
- [ X ] `CONTRIBUTING.md` rule-authoring guide (Section 15). A demo GIF, if one is added, comes from a real run. Do not draw frames that did not happen.
- [ X ] Issue templates for bug, false positive, missed attack, and new rule (Section 15).

The draft's older wording is not carried, because this file already replaced it:

- [ X ] The 0.1.0 release-status table (0.1.0 and later versions exist).
- [ X ] Linux and macOS only. Windows is in the matrix.
- [ X ] The note that runtime hooks load `node:sqlite` eagerly.
- [ X ] Decoy-route hits as critical, and auto-block on a route hit. Decoy routes stay low. A canary credential is the critical event.
- [ X ] A `pr-review` bot that comments on pull requests (Section 31).
- [ X ] Writing an override into the lockfile. Overrides write `package.json` and print `run npm install`.
- [ X ] Publishing with `npm@latest`. The publish job pins npm 12.2.0.
- [ X ] Phases 25–35 as not started. They are done (Section 25).

---

## 34. Shipped in 0.3.0

That file is deleted. This section is the record. It is not the next queue (Section 32). Default `scan` stays the same unless a flag below is set. Nothing here is a recall claim.

### In 0.3.0

- [ X ] CI reports (`FULLSHIELD_EXPERIMENTAL_CI_REPORTS=1`): `--github-annotations`, `--junit`, `--gitlab`.
- [ X ] Scan diff (`FULLSHIELD_EXPERIMENTAL_DIFF=1`): compares two `scan --json` files. The match key ignores the line number. It uses rule, file, severity, and the snippet or message. Two findings that share that text stay distinct. A line shift is a move, not a new finding. A changed message with the same finding id is a move.
- [ X ] GitLab Code Quality `fingerprint` uses that same line-independent value.
- [ X ] SARIF is `scan --sarif`. It was already implemented. Every report format (console, JSON, SARIF, Markdown, HTML, GitHub annotations, JUnit, GitLab) masks AWS, GitHub, Stripe, and Slack token shapes to the first 4 characters plus `****` before writing them.
- [ X ] Baseline file `.fullshield-baseline.json` may include `suppressions`. Each row needs `ruleId`, `owner`, `reason`, and an ISO `expires`. Optional `file`. A future row hides that finding. A missing field or a past date does not hide it, and the scan exits 1. Rewriting the baseline keeps the suppression rows.
- [ X ] GitHub Actions, still behind `FULLSHIELD_EXPERIMENTAL_IAC=1`: unpinned actions, `pull_request_target`, broad permissions, secret logging, plus `IAC-GHA-INJECT-001` (`${{ github.event.* }}` inside `run:`) and `IAC-GHA-PRCHECKOUT-001` (that trigger also checks out pull-request code).
- [ X ] Lockfile checks in `checkLockfileIntegrity`: non-https or non-`registry.npmjs.org` resolved URLs (`SUPPLY-LOCKURL-001`), and a resolved entry with no integrity (`SUPPLY-LOCKINTEGRITY-001`). Called by the supply helpers, not by default `scan`.
- [ X ] Dependency confusion (`SUPPLY-CONFUSION-001`) already exists behind `FULLSHIELD_EXPERIMENTAL_VEX=1`. `checkProvenance(previouslyHad, currentlyHas)` returns `SUPPLY-PROVENANCE-001` only when the caller passes `true, false`. It does not compare two published versions by itself. A local cache file can say whether one exact `name@version` had provenance. A missing file stays unknown.
- [ X ] Git history secrets already exist behind `FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1` and `scan --history`. The walk stops after 500 commits (`FULLSHIELD_HISTORY_MAX`, clamped to 1–5000). When that cap drops older commits, console and JSON say `scanned N of M commits`. The secret text in those findings is masked.
- [ X ] Copyleft notice (`FULLSHIELD_EXPERIMENTAL_LICENSE=1`): `DEPS-LICENSE-001` when an installed direct dependency's `package.json` says GPL or AGPL. No `node_modules` means no finding. LGPL is not flagged. The license is read, not guessed.

### Already in the product then, not rebuilt for 0.3.0

- [ X ] Config file is `fullshield.config.json` (modules, `failOn`, path `ignore`, baseline path, SAST size). Severity overrides and exceptions with owner, reason, and expiry are `fullshield.policy.json` (`FULLSHIELD_EXPERIMENTAL_POLICY=1`). A second `.fullshield.yml` is not added.
- [ X ] `scan --staged` scans the git index for pre-commit.
- [ X ] Incremental scan is `scan --changed` / `--since` behind `FULLSHIELD_EXPERIMENTAL_PLATFORM=1`.
- [ X ] `listWorkspaces` reads npm and pnpm workspace globs behind that same flag. It does not scan each workspace with its own lockfile. Per-workspace lockfile scans are Phase 54.
- [ X ] Offline OSV cache is `scan --offline` / `--offline-safe`.
- [ X ] Framework header, CORS, and cookie checks already exist as config and experimental class rules.

### Not in 0.3.0

- [  ] Custom SAST or secret rules in YAML or JS. That is Phase 57, behind its flag.
- [  ] A pull-request comment bot. Still rejected (Section 31).
- [  ] A VS Code extension. Still rejected (Section 31).
- [  ] Per-workspace lockfile scans. That is Phase 54, behind its flag.

---

## 35. Shipped in 0.4.0

That file is deleted. This section is the record. Do not rebuild the same-function Mongo filter. Next work is Phase 47. Ground truth is not edited. Nothing is marked `reviewed: true`. `package.json` `engines` is `>=22.13`.

### Rules that still apply

- [ X ] No edit to `bench/*/ground-truth.json` or triage files to improve a score.
- [ X ] A human labels findings. Blank `label`, `reviewer`, and `note` cells stay blank.
- [ X ] `clean-app` stays at 0 findings.
- [ X ] A change to default `scan` output needs `bench/snapshots/HEAD.json`, `bench/snapshots/DIFF.txt`, and a CHANGELOG entry under "Default scan changes".
- [ X ] A speed-versus-accuracy tradeoff stops for a human decision.
- [ X ] New behavior that would change default findings is not shipped that way unless the snapshot diff is recorded.

### Already done (do not rebuild)

Phases 1–6 in `docs/history/STABILIZATION-PLAN.md` are already in `0.3.0`: `docs/NOISE-REPORT.md`, dependency grouping, SAST sink-line dedupe, default excludes, `SAST-SKIP-001`, streaming parse, `bench/review/*.csv` with blank labels, Node 20, and `COMPARISON.md` plus `bench/class-map.json`. Those counts are unreviewed. They are not a precision or recall claim. Node 20 support is removed by Phase 46.

### What is still weak

Default scan on NodeGoat is still 256 findings against about 7 in-scope ground-truth bugs. After grouping, the rest is mostly one `DEPS-VULN-001` row per package and advisory, including packages the app does not import. Hiding those would cut the number and also hide real advisories. That tradeoff is not taken. Phase 47 folds the console view and leaves the JSON list complete.

Stored XSS in Swig `layout.html` (NodeGoat A3) is still missed. Swig prints `{{ name }}` raw. Handlebars uses the same braces and escapes them. Flagging every `{{ }}` in `.html` would mark safe templates. That tradeoff is not taken. Phase 50 flags `{{ }}` only when the view engine is raw.

NoSQL was the gap that could be closed without that tradeoff. A filter written inline (`User.find({ name: req.body.name })`) was found. The same object stored in a variable and passed later was not, because the query saw only the variable name.

### The 0.4.0 change

`User.find(filter)` is reported when `filter` was built from request input in the same function: an object literal, a later property write, a spread of `req.body`, an array of request values, `Object.assign`, or a copy of such a variable. A literal-only object is not reported. A field passed through `mongoSanitize` or a schema parse is not reported. Sequelize, Prisma, TypeORM, Knex, and Drizzle files are still not treated as Mongo. This uses the existing rule `SAST-NOSQLI-001`. It does not add a flag.

SAST was re-scanned on the pinned apps. NodeGoat, Juice Shop, DVNA, and goof kept the same SAST keys. vulnerable-node gained two keys, `routes/shop.js` lines 41 and 58, which are the unreviewed in-scope NoSQL entries. A helper in the same file, and a nested function that uses the filter, are reported as well. That second pass added no further keys on the pinned apps. A filter returned from another file is still missed (Phase 51). Package version is `0.4.0` because the default scan count changed. It is not a publish by itself. Nothing was pushed.

---

## 36. Cursor Work Order 2026-10-18 (record — superseded by Section 40)

This is the queue for a single long Cursor session. It does not override Section 0. If anything here conflicts with R1–R22, Section 0 wins and Cursor stops (S7).

### 36.1 Start of day (once)
1. `git switch next && git pull`. Confirm `npm run verify` passes on the untouched tree. Paste the summary table. If it fails, stop (S4). Do not fix forward on a red baseline.
2. Record `node scripts/default-scan-diff.mjs` output against `bench/snapshots/HEAD.json`. It must be empty before any phase starts.
3. Create one worktree per lane below (R21): `git worktree add ../fs-<phase> -b phase-<N> next`.

### 36.2 Lanes

Three lanes. Lane A is sequential and is the priority. Lanes B and C only run while Lane A is blocked on a human, or after Lane A's last item for the day is done. Never let B or C delay A.

**Lane A — the product change (sequential, merge into `next` in this order):**

| Order | Phase | Stable output change? | Gate before next item |
|---|---|---|---|
| A1 | 46 Runtime floor + README version | No | `verify` green on Node 22 and 24 |
| A2 | 47 Actionable console | No (console only) | Phase 47 acceptance passes + NodeGoat shown-count reported (47.1) |
| A3 | 48 Unused dependency removal | No | acceptance passes |
| A4 | 49 Upgrade plan | No | acceptance passes |
| A5 | 75 Router-level auth inheritance | **Yes (R10)** | Build to snapshot diff, then STOP. Do not merge. |
| A6 | 50 Template-engine-aware XSS | **Yes (R10)** | Build to snapshot diff, then STOP. Do not merge. |
| A7 | 51 Cross-file returns | **Yes (R10)** | Build to snapshot diff, then STOP. Do not merge. |
| A8 | 52 Phantom and mismatched deps | **Yes (R10)** | Build to snapshot diff, then STOP. Do not merge. |

A5–A8 each live on their own `phase-N` branch off `next` (after A4 is merged). Each one ends with `bench/snapshots/DIFF.txt` for that branch and a report under 0.8 with "Needs human decision: approve stable diff". They are not merged into `next` today. They do not depend on each other.

**Lane B — evidence tooling (dev scripts only, not shipped in the tarball, no product flag):**

| Order | Phase | Why today |
|---|---|---|
| B1 | 67 Human review CLI | Nothing is reviewed. This removes the friction for the human, it does not do the review. |
| B2 | 68 Holdout freeze + one-shot run script | Makes B3 in Section 3 enforceable by a script instead of memory. |
| B3 | 73 Promotion evidence report | Produces evidence only. Nothing is promoted. |

**Lane C — experimental features (each behind its own flag; default scan unchanged):**

| Order | Phase | Flag |
|---|---|---|
| C1 | 70 Install-time stealer and C2 heuristics + security-placeholder check | `FULLSHIELD_EXPERIMENTAL_SUPPLY` (existing) |
| C2 | 60 `fullshield explain <id>` | `FULLSHIELD_EXPERIMENTAL_EXPLAIN` |
| C3 | 61 Reachability evidence | `FULLSHIELD_EXPERIMENTAL_REACH_EVIDENCE` |
| C4 | 62 Lockfile PR diff | `FULLSHIELD_EXPERIMENTAL_DEPS_DIFF` |
| C5 | 63 Modern lockfile formats | `FULLSHIELD_EXPERIMENTAL_LOCKFILES` |
| C6 | 74 SARIF v2 fields | `FULLSHIELD_EXPERIMENTAL_SARIF_V2` |
| C7 | 64 Config-declared sources and sanitizers | `FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS` |
| C8 | 66 Reachability in SBOM | `FULLSHIELD_EXPERIMENTAL_SBOM_REACH` |
| C9 | 71 RASP sink coverage | `FULLSHIELD_EXPERIMENTAL_RASP` (existing) |
| C10 | 72 RASP DNS pin store | `FULLSHIELD_EXPERIMENTAL_RASP` (existing) |
| C11 | 65 Taint function summaries | `FULLSHIELD_TAINT_SUMMARIES` |
| C12 | 69 Secret rotation playbooks | docs only |

Lane C items merge into `next` one at a time, in the order above, each after `verify` + an empty `default-scan-diff` (R20). If a Lane C item cannot meet acceptance, leave it on its branch, report it (S3), and move to the next one.

Not today: 53, 54, 55, 57, 58, 59 (after Lane A's stable-output phases are approved), and 56 (blocked on an R15 amendment).

### 36.3 Hard stops for today
- [  ] Any Lane A stable-output phase: stop at the diff. Merging it is a human decision (R10).
- [  ] Any phase that needs a test, fixture, `expected-findings.json`, `ground-truth.json`, or `triage.json` edited: stop (S2).
- [  ] Coverage within 2 points of a threshold after a merge: stop (S5).
- [  ] No tag, no publish, no push to `main`, no version bump beyond what R16 requires on `next`. The human releases (Section 2).
- [  ] Never set `"reviewed": true`. Never fill a `label`, `reviewer`, or `note` cell.

### 36.4 End of day
One message containing, in order:
1. A per-phase report in the 0.8 format for every phase touched today, including ones left unfinished.
2. A table: `phase | branch | merged into next | flag | tests added | default-scan-diff (EMPTY / DIFF.txt path)`.
3. The list of human decisions waiting, one line each, with the file the human should open.
4. `npm run verify` summary table on `next` after the last merge.

Update Section 30 in the same commit as the last merge of the day.

---

## 37. Advanced Phases 60–75

Rules that apply to every phase in this section, in addition to Section 0:
- [  ] Experimental unless the phase says "R10". A new command, flag, export, or rule ID is a minor bump (R16).
- [  ] Every new CLI failure path gets an `FS-E###` code appended to `docs/errors.md` and `src/cli/errors.ts` in the same commit (Phase 44 contract). Do not renumber existing codes.
- [  ] Every new rule ID gets `rules/<ID>.md`, a positive fixture, a negative fixture, a failing test first (R4), a compliance-map row (Section 22.6), and a mutation-smoke target.
- [  ] Fixtures are written from scratch (B8). Never copy benchmark-app or real malware code. Malware-shaped fixtures are inert: no live hosts, no real wallet addresses, no working payload.
- [  ] No new hard dependency (R13). No new network host (R15).
- [  ] `clean-app` stays at 0 findings with each flag on and off (R12).

### 47.1 Addendum to Phase 47 (human decision 2026-10-18 (D4))
These two items are part of Phase 47's acceptance. The shown rule is the one in Section 32 Phase 47, not the earlier severity-or-confidence rule. Human decision 2026-10-18 (D4) removes the 40-row stop. Acceptance is: the D3 shown rule passes its tests, and the per-app table below is recorded in CHANGELOG under Unreleased and in this Phase 47 report. There is no row-count threshold. Do not change the shown rule, the 20-row cap, or any severity.

1. **Order inside the shown list:** `DEPS-MALICIOUS-001` first; then severity, highest first; then reachability `reachable` / `symbol-reachable`, then `reachable-via-dependency`, then `reachability-unknown`, then findings with no reachability field; then file, line, ruleId. Console only. JSON, SARIF, and `sortFindings` for other reporters are unchanged. Dependency rows are grouped by package name before this order is applied. The row uses the group's highest severity and best reachability.
2. **Record the recount:** print `app | shown rows (grouped) | shown findings | folded findings | shown findings by reachability class` for every tuning app. The 2026-10-18 recount is accepted. There is no row-count threshold.

Accepted 2026-10-18 from the existing offline-safe JSON (unreviewed). Human decision 2026-10-18 (D4). The shown rule was not changed.

| app | shown rows | shown findings | folded findings | shown findings by reachability |
|---|---|---|---|---|
| nodegoat | 36 | 62 | 194 | reachable-via-dependency 41, reachable 12, none 8, not-imported 1 (`DEPS-MALICIOUS-001` fsevents) |
| juice-shop | 49 | 59 | 46 | none 46, reachable 13 |
| dvna | 14 | 16 | 7 | none 12, reachable 4 |
| goof | 63 | 157 | 114 | reachable-via-dependency 86, reachable 60, none 11 |
| vulnerable-node | 41 | 43 | 20 | none 38, reachable-via-dependency 4, reachable 1 |

### [X] Phase 60 — Offline finding explainer [`FULLSHIELD_EXPERIMENTAL_EXPLAIN`]
`fullshield explain <findingId>` reads the last scan (`.fullshield/last-scan.json`) or `--from <scan.json>` and prints one finding in full: rule title, severity, confidence, file:line with 5 lines of context read from disk, the full `trace`, the reachability class with its dependency path, the fix proposal diff if any, and the path to `rules/<id>.md`. No AI. No network. Deterministic.

- [x] An id prefix of at least 6 characters is accepted when it matches exactly one finding. Ambiguous or missing ids exit 2 with an `FS-E` code and list up to 5 candidates.
- [x] Secrets stay masked. A snippet is re-read from disk and masked again before printing, because the file may have changed since the scan.
- [x] The MCP `explain_finding` tool may call the same renderer. It stays read-only.

Acceptance: golden-file tests for a SAST finding with a 3-file trace, a reachable dependency finding, a secret finding (masked), and an ambiguous prefix. A test asserts zero network calls.

### [X] Phase 61 — Reachability evidence [`FULLSHIELD_EXPERIMENTAL_REACH_EVIDENCE`]
For each `DEPS-VULN-001` and `DEPS-MALICIOUS-001`, record why the reachability class was chosen, as an optional `reachabilityEvidence` field:

```ts
reachabilityEvidence?: {
  imports: Array<{ file: string; line: number; specifier: string }>;   // up to 5, first by file then line
  calls?: Array<{ file: string; line: number; symbol: string }>;        // only when symbol data exists
  dependencyPath?: string[];                                           // e.g. ['express', 'body-parser', 'qs']
  reason: string;                                                       // one sentence, deterministic template
}
```

- [x] `not-imported` records `imports: []` and a reason that names the roots that were checked (production entry files, not test files).
- [x] `reachability-unknown` records which lockfile property was missing.
- [x] The field is added to JSON only when the flag is on. `(ruleId, file, line, severity)` keys are unchanged. Console shows the first import line under each shown dependency finding.

Acceptance: fixtures for each reachability class assert the evidence. A test asserts the field is absent with the flag off. A test asserts no evidence entry points into `test/` or a devDependency-only file for a production finding.

### [X] Phase 62 — Lockfile PR diff [`FULLSHIELD_EXPERIMENTAL_DEPS_DIFF`]
`fullshield deps-diff <base-ref>` compares the lockfile at a git ref with the working tree. It reads the old lockfile with `git show <ref>:<path>`. It never checks out the ref and never runs `npm install`.

Output:
- [x] Packages added, removed, upgraded, downgraded (name, old version, new version, direct or transitive, path from a direct dep).
- [x] Advisories introduced by the change and advisories cleared by it, from OSV (cache first, `--offline` honored).
- [x] For each **added** package version: publish age and whether that version has install scripts, from `registry.npmjs.org` (allowed host, R15). Versions younger than `deps.minReleaseAgeHours` (default 72) are listed as `new-release`. Missing registry data stays `unknown`. Never guessed.
- [x] `--json` for CI. `--fail-on <severity>` applies only to advisories introduced by the diff.

Acceptance: a fixture git repo with two lockfile commits (fixture OSV cache, mocked registry). Added, removed, upgraded, and an introduced advisory each appear. A downgrade that introduces an advisory exits 1 with `--fail-on high`. A test asserts no `git checkout`, no `npm` child process, and only allowlisted hosts.

### [X] Phase 63 — Modern lockfile formats [`FULLSHIELD_EXPERIMENTAL_LOCKFILES`]
Parse packages **and dependency edges** from:
- [x] yarn berry (`yarn.lock` with `__metadata`), including `npm:` aliases and `patch:` protocols (patch protocol resolves to the underlying version).
- [x] pnpm lockfile v9 (`importers`, `packages`, `snapshots` split).
- [x] Bun text lockfile `bun.lock` (JSONC). The binary `bun.lockb` is not parsed; it yields `DEPS-NOLOCK-001`-style info that the format is unsupported and keeps `reachability-unknown`.

A format that parses packages but not edges sets `edgesKnown: false` → `reachability-unknown` (never a silent downgrade). With the flag off, these files behave exactly as today.

Acceptance: one fixture per format with a known vulnerable transitive package reached through a direct dep, and one unused package. Classes match the npm-lockfile equivalent fixture. A YAML parser, if needed for pnpm v9, is an optional peer, lazy-loaded, with an install hint (R13). A test asserts default scan output is unchanged on all existing fixtures.

### [X] Phase 64 — Config-declared sources and sanitizers [`FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS`]
Smaller than Phase 57. Teams can name their own helpers in `fullshield.config.json`:

```json
"sast": {
  "sources":    [{ "callee": "getUserInput", "returns": "tainted" }],
  "sanitizers": [{ "callee": "escapeSql", "clears": ["sqli"] },
                 { "callee": "safePath", "clears": ["path"] }]
}
```

- [x] `clears` takes the B4 class names only. A sanitizer clears taint only for the listed classes (Section 6.2 rule).
- [x] Callee matching is by imported binding (`import { escapeSql } from './db'`) or local function name. Not by string search.
- [x] With the flag off, these keys are rejected with an `FS-E` code (unknown-key behavior is preserved for everyone else).
- [x] A config sanitizer never clears `DEPS-*` or `SECRET-*` findings.

Acceptance: a positive fixture (custom source reaches a SQL sink), a negative fixture (custom SQL sanitizer clears it), and a cross-class negative (the SQL sanitizer does not clear a path finding on the same value). Default config scan unchanged.

### Phase 65 — Taint function summaries [`FULLSHIELD_TAINT_SUMMARIES`]
Performance only. Cache per-function taint summaries (which params flow to the return value, which params reach which sink class) keyed by sha256 of file content + FullShield version + config hash. Reuse them across files and across warm/incremental scans instead of re-walking callee bodies.

- [x] Output must be byte-identical with the flag on and off (sorted JSON). This is the main acceptance test, run on vulnerable-app, clean-app, and every bench app.
- [x] Cache lives under the existing parse cache directory. A corrupted cache entry is discarded, never trusted.
- [  ] Target: nest and undici `--changed` p50 under the 5 s incremental target from Phase 42. If the target is not met, report the numbers (Section 28); do not trade accuracy for speed (STABILIZATION-PLAN rule 8 — stop and ask).

Acceptance: identical-output test; cache-invalidation test (edit a callee, the caller's finding updates); `bench/perf-baseline.json` updated with before/after on the same machine.

### [X] Phase 66 — Reachability in SBOM and VEX [`FULLSHIELD_EXPERIMENTAL_SBOM_REACH`]
`fullshield sbom --format cyclonedx` adds, per component with an advisory, CycloneDX `properties`:
- [x] `fullshield:reachability` = the class
- [x] `fullshield:dependencyPath` = the path string when known
- [x] `fullshield:devOnly` = `true` / `false`

VEX output (existing `vex` command) cites the same evidence in `detail` when Phase 61's evidence exists. `not_affected` rules are unchanged: only `not-imported`.

Acceptance: CycloneDX 1.5 validation still passes. Properties absent with the flag off. A malicious package component never carries a downgrading statement.

### [X] Phase 67 — Human review CLI (dev tooling, not shipped)
`node bench/review-cli.mjs --app <name> [--findings | --ground-truth]` walks a human through review in the terminal.

- [x] Ground-truth mode: for each entry shows the cited source link, the file excerpt at that line, class, and in/out-of-scope. Keys: `y` confirm, `n` reject with a required reason, `s` skip, `q` quit. Writes `bench/<app>/review-log.json` with reviewer name (asked once, from `git config user.name` as the default), timestamp, decision, reason.
- [x] Findings mode: reads `bench/review/<repo>.csv`, shows the 5-line snippet, and writes `label` (`TP` / `FP` / `unsure`), `reviewer`, `note`.
- [x] `reviewed: true` is set on an app's `ground-truth.json` only after every entry has a decision **and** the human types the app name to confirm.
- [x] The script refuses to run when stdin is not a TTY, when `CI` is set, or when `CURSOR_AGENT`/`FULLSHIELD_AGENT` env is set. Cursor builds and tests it with an injected fake TTY in tests only. Cursor never runs it against real files.
- [x] Not in `package.json` `files`. `pack-budget` asserts it is not packed.

Acceptance: tests with an injected input stream cover confirm, reject-requires-reason, resume after quit, and the non-TTY refusal. A test asserts no file under `bench/` changes when the refusal triggers.

### [X] Phase 68 — Holdout freeze and one-shot run (dev tooling)
`node bench/holdout-run.mjs --release <version>` enforces B3:
- [x] Refuses unless `HEAD` is tagged `freeze-<version>` and no file under `src/modules/` or `rules/` changed since that tag.
- [x] Runs default scan once on each `untouched` app in `bench/holdouts.json`, writes `bench/results/<app>-<version>.json`, sets `firstRunDate`, flips status to `seen`, and refuses to run a second time for the same app.
- [x] Leaves at least 2 untouched apps (B3). If running would leave fewer, it refuses and says so.
- [x] Recall printed only against `reviewed: true` ground truth; otherwise labeled `unreviewed`.

Acceptance: tests on a fixture holdouts file cover freeze-tag missing, rule file changed after freeze, second run refused, and reserve-floor refusal. Cursor does not run it on the real holdouts (human-only, Section 2 step 5).

### [X] Phase 69 — Secret rotation playbooks (docs only)
For each secrets rule, `rules/<ID>.md` gains a "Rotate" section: where to revoke, how to issue a new key, how to find where the old key was used, and that removing it from git history does not un-leak it. Providers: AWS, GitHub, Stripe, Slack, Google, OpenAI/Anthropic-style keys, PEM keys, DB URLs, JWT and session secrets.

- [x] Docs only. Remediation strings in findings are not changed (that would be a message change on stable output; not worth an R10 for docs).
- [x] Every external link is to the provider's own documentation domain. A link-check test (Phase 44) covers them.

### [X] Phase 70 — Stealer, chain-C2, and security-placeholder heuristics [`FULLSHIELD_EXPERIMENTAL_SUPPLY`]
Static only, inside the existing `install` guard and the supply helpers. Never executes or installs the analyzed package (R15). Motivation: npm campaigns in 2026 that used platform-gated loaders, credential stealers, and blockchain lookups for command-and-control.

New rule IDs:

| ID | Detects | Severity |
|---|---|---|
| `SUPPLY-CHAINC2-001` | Package code that queries a public blockchain RPC (Solana/Ethereum JSON-RPC method names such as `getSignaturesForAddress`, `eth_getLogs`) **and** then fetches or evaluates a value derived from that response | high |
| `SUPPLY-STEALER-001` | Reads of browser profile stores, Discord/Telegram local storage, or crypto-wallet extension directories **combined with** any network call | critical |
| `SUPPLY-PLATFORMGATE-001` | A `process.platform === 'win32'` (or `os.platform()`) branch that downloads a file **and** spawns or writes an executable, in install scripts or package entry code | high |
| `SUPPLY-SECHOLDER-001` | A lockfile entry for a package whose registry `latest` is `0.0.1-security` (npm's removed-for-security placeholder) while the locked version is not that placeholder | critical |

Rules:
- [x] Each detector requires the combination listed. A single signal (only a wallet path string, only an RPC method name, only a platform check) is not a finding. Negative fixtures prove that.
- [x] `SUPPLY-SECHOLDER-001` reads `registry.npmjs.org` only, honors `--offline` (cache only, missing data = no finding), and is never downgraded by reachability, same as `DEPS-MALICIOUS-001`. Remediation: remove the package, delete `node_modules`, reinstall from a clean lockfile, rotate any credential the machine could read.
- [x] Fixtures are inert strings and dead code paths. No real wallet addresses, RPC endpoints, or payload URLs. Hosts in fixtures use `example.invalid`.

Acceptance: positive + negative fixture per rule; registry mocked; a test asserts that with `FULLSHIELD_EXPERIMENTAL_SUPPLY` unset, default `scan` emits none of these IDs.

### [X] Phase 71 — RASP sink coverage [`FULLSHIELD_EXPERIMENTAL_RASP`]
Close the "Not covered" rows in `RASP-SINKS.md` that do not break the host:
- [x] `mongodb` `Collection.prototype.findOne`, `aggregate`, `updateOne`, `updateMany`, `deleteOne`, `deleteMany`, `countDocuments` (filter and pipeline `$` operators from user input).
- [x] `mongoose` `Query.prototype` `findOne`, `updateOne`, `updateMany`, `deleteOne`, `deleteMany`, `countDocuments`, and `Model.aggregate`.
- [x] `axios` `put` / `patch` / `delete` / `head` / `options` and instance clients from `axios.create()`.
- [x] `undici.request` and `undici.Dispatcher` / `Agent` `request` (SSRF host check).
- [x] `diagnostics_channel` subscription for `undici:request:create` where available, as a second signal (not a replacement for the wrap).

Every new hook fails open (`RASP-FAIL-OPEN-001`). `RASP-SINKS.md` is updated in the same commit.

Acceptance: ≥ 10 attack and ≥ 10 benign cases per new sink group in the corpus (R8a applies to any reclassification). Benign stays 0 blocked. Express + parameterized query p95 stays under 1 ms.

### [X] Phase 72 — RASP DNS pin store [`FULLSHIELD_EXPERIMENTAL_RASP`]
Close the "sticky DNS-rebinding pin" gap. When a request-derived host is resolved for an outbound call, pin the resolved address set for that host for `rasp.dnsPinTtlMs` (default 60 000) inside the current request context, and refuse a later connection in the same request to a different, private, loopback, link-local, or metadata address for that host.

- [x] Store is in-memory and LRU-capped (default 1 000 hosts). No persistence across processes.
- [x] Fails open on resolver errors, consistent with the rest of RASP.

Acceptance: a mock resolver that returns a public IP first and `127.0.0.1` second is blocked on the second connection within the TTL and allowed after expiry when the second address is public. Benign corpus 0 blocked.

### [X] Phase 73 — Promotion evidence (process, no promotion)
Run `scripts/promotion-report.mjs` for `FULLSHIELD_EXPERIMENTAL_TAINT_V2`, `_SAST_GAPS`, `_FRAMEWORKS`, and `_CLASSES` against Phase 43 criteria. For each flag, produce `bench/promotion/<flag>.md` with: tuning-app key diff with the flag on vs off (labeled `seen`), crash count on the `bench/realworld.json` corpus, default-scan-diff if promoted, and the list of criteria not met.

- [x] Cursor does not promote anything (R1, R11). The report is evidence for the human.
- [x] Untouched holdouts are not scanned (B3). Where a criterion needs an untouched app, the report says "unmet — needs Phase 68 run after review".

### [X] Phase 74 — SARIF v2 fields [`FULLSHIELD_EXPERIMENTAL_SARIF_V2`]
With the flag on, `scan --sarif` adds:
- [x] `partialFingerprints.fullshield/v1` = the line-independent diff key from Section 34, so GitHub code scanning does not reopen alerts when lines shift.
- [x] `relatedLocations` for every dependency path step (manifest line of the direct dep) and for every `trace` step not already in `codeFlows`.
- [x] `rules[].help.markdown` from `rules/<ID>.md` (first 2 KB) and `rules[].properties.precision` = `"unreviewed"` until the human has reviewed precision for that rule.
- [x] `properties.reachability` on each result for dependency findings.

Default SARIF is unchanged with the flag off (GitHub alert identity would otherwise change for every user).

Acceptance: SARIF 2.1.0 schema validation passes. A test shifts a finding by 3 lines and asserts the fingerprint is unchanged. A test asserts byte-identical default SARIF with the flag off.

### Phase 75 — Router-level auth inheritance (R10, precision)
`SAST-AUTH-001` currently treats each route alone. Recognize auth middleware mounted before the route on the same router or app: `router.use(requireAuth)` then `router.get(...)`; `app.use('/admin', requireAuth, adminRouter)`; NestJS `@UseGuards` on the controller class when `--experimental-frameworks` is on.

- [x] Order matters: middleware mounted after the route does not cover it.
- [x] Path-prefixed `app.use('/api', auth)` covers only routes mounted under `/api`.
- [x] Auth recognition uses the existing auth-name heuristics. Do not widen the name list in this phase.
- [x] Cross-file: a router imported into the app file inherits middleware mounted on its mount path (existing module graph, depth 5).

This removes findings, so it changes stable output (R10). Snapshot diff required. Do not edit ground truth.

Acceptance: positive fixture (middleware mounted after the route — still flagged), negative fixtures (router-level `use`, app-level prefixed `use` with a router from another file). `clean-app` stays at 0. `bench/snapshots/DIFF.txt` lists every removed `SAST-AUTH-001` key; the report notes which removed keys, if any, match unreviewed ground-truth entries (expected: none, since AUTH is low-confidence and out of the B4 in-scope list — confirm, do not assume).

---

## 38. Advanced points — production reliance

These points constrain README, release notes, and later phases (Section 4.4, R7). They are not a queue and they do not add a phase. A later phase may narrow a gap. It does not delete the point until a human-reviewed measurement says the gap is gone.

1. [  ] **Semgrep still overlaps on injection, and its rule set is larger.** On the same tuning apps, Semgrep Community Edition still reports injection classes that overlap FullShield's SAST rules. Semgrep's public rulesets are much larger and cover more than JavaScript and TypeScript. FullShield is JS/TS only (Section 4.3). The local comparison is `COMPARISON.md` (one run on 2026-10-16, unreviewed, not a recall claim). Do not write that FullShield matches or beats Semgrep.

2. [  ] **npm audit and OSV-Scanner stay the mature dependency databases.** FullShield queries OSV (`https://api.osv.dev`) and can read `npm audit --json` (R6). It does not replace either tool. Reachability is a layer on top of those alerts, not a second advisory database. Section 47 is the plan that narrows the npm gap (lockfile truth, packument, tarball bytes, lifecycle scripts, name trust, per-instance graph). This point stays until a human-reviewed comparison says a specific check is no longer a gap.

3. [  ] **The full cycle is not a guarantee.** Runtime blocking, exploit confirmation, and auto-remediation pull requests are experimental and fail-open. The stable runtime piece is a monitor. `monitor` is the production default (Section 5). It does not guarantee that an attack is stopped. `--fail-on` is the CI gate. The agent never merges and never posts to GitHub (Section 22.8, Section 31).

4. [  ] **Large apps are slow.** Phase 42's cold target is 60 seconds. The stored local run in `bench/perf-baseline.json` (`measuredAt` 2026-10-16) has the Next.js sample (`bench/realworld.json`, repo `vercel/next.js`, pin `a6d4c15991fd2f69c14eea4e8b655b596bc162bf`) at a cold p50 of 71746.763708 ms, about 72 seconds, with warm and incremental runs in the same range. That number is a local measurement, labeled unreviewed. It is not a headline. Phase 42 and Phase 65 may improve it. They do not trade accuracy for speed, and they do not rewrite this point with a new number unless that number comes from a new stored run.

5. [  ] **How to use it beside other tools.** Use FullShield as a Node-only CI gate (`scan --fail-on high`) and as a reachability layer on dependency alerts. Do not drop Semgrep, npm audit, OSV-Scanner, or a secrets scanner because this package exists. Secrets rules here do not retire Gitleaks or TruffleHog (Section 4.4).

---

## 39. Leadership Phases 76–93 (rev 2026-10-19)

### 39.0 Why these phases, and what they cannot do
The 2026-10-18 market read was: a useful Node-only add-on, not a category leader. These phases target the measured weak points, in this order of importance:

| Weak point (measured or stated in this spec) | Phases |
|---|---|
| Precision is not measured. All ground truth is `reviewed: false`. | 76, 77 (tooling); the review itself is human-only (R1) |
| Large apps are slow: Next.js cold p50 ≈ 72 s vs 60 s target; Phase 65 nest/undici 5 s target unmet | 78, 79, 88 |
| Noise: NodeGoat JSON 256 vs about 7 in-scope real bugs | 80, 81, 82, 84 |
| Semgrep has a larger rule set; npm audit / OSV-Scanner are the mature databases (Section 38) | 83, 90 (be the layer beside them, not a replacement) |
| Supply-chain detection is mostly advisory lookup plus install-script heuristics | 86, 87 |
| Findings are a list, not a story a developer can act on | 84, 85, 91 |
| SBOM is CycloneDX only | 89 |
| Repo hygiene items still open (issue templates, branch protection) | 92 |
| 20+ experimental flags, nothing promoted | 93 (evidence only) |

No phase here lets README, CHANGELOG, or any copy say "number 1", "best", "leader", "one of a kind", "complete protection", or "prevents attacks". Position is earned by numbers from human-reviewed ground truth (R7) and is stated as numbers, not adjectives.

### 39.1 Rules for every phase in this section (in addition to Section 0 and the Section 37 header rules)
- [  ] Experimental behind its own flag unless the phase says "R10" or "dev tooling". New command/flag/export/rule ID = minor bump (R16).
- [  ] No new hard dependency (R13). Optional peers are lazy-loaded with an install hint and an `FS-E###` code.
- [  ] No new network host (R15). Phases 83, 86, 89, 90 are local-file only. Phase 87 uses `registry.npmjs.org` only.
- [  ] Byte-identical default `scan --json` with every new flag off. A test per phase asserts it on vulnerable-app, clean-app, and every bench app (R9).
- [  ] `clean-app` stays at 0 with each flag on (R12).
- [  ] Every number in a phase report is from a stored run (`bench/perf-*.json`, `bench/precision/*.json`) and labeled `reviewed` or `unreviewed`.
- [  ] Untouched holdouts are never scanned by these phases (B3). Only the Phase 68 one-shot script may scan them, after the human says so.

### Phase 76 — Precision sampling harness (dev tooling, not shipped)
Precision has never been measured. Build the tool that lets the human measure it in about an hour.

- [  ] `scripts/precision-sample.mjs --app <name> --per-rule 10 --seed <n>`: deterministic sample (seeded) of up to N findings per rule ID from the default scan of tuning and seen apps. Writes `bench/precision/<app>.todo.json` with `label: null`, `reviewer: null`, `note: null` for every row.
- [  ] Plugs into the Phase 67 review CLI so the human labels `tp` / `fp` / `unsure` in the terminal with the code snippet (±5 lines) and the trace shown.
- [  ] `scripts/precision-report.mjs` computes per-rule precision **only from rows the human labeled**, with Wilson 95% interval and n. Rules with n < 10 print `insufficient sample`. Output `bench/precision/REPORT.md`.
- [  ] Cursor never fills a `label`, `reviewer`, or `note` cell (Section 36.3). A test asserts the sampler writes `null` for all three.
- [  ] Not in the npm tarball (`pack-budget` test asserts `bench/precision` and both scripts are absent).

Acceptance: sampler is deterministic for a fixed seed (test). Report on a fixture todo file with hand-written labels produces the expected precision and interval (test). Report refuses to run on a file with zero labels and says so.

### Phase 77 — Real-world precision regression gate (dev tooling + CI job on `next`)
New findings on real code are the noise users see. Freeze them.

- [  ] `bench/snapshots/realworld.json`: default-scan keys `(ruleId, file, line, severity)` for every pinned repo in `bench/realworld.json`. Generated by `scripts/realworld-snapshot.mjs`. Repos are cloned at their pin into a cache dir, never executed, never installed.
- [  ] `scripts/realworld-diff.mjs` prints added and removed keys per repo and exits 1 on any **added** key unless `bench/snapshots/realworld-approved.txt` (human-edited only, R1) lists it.
- [  ] CI: a separate job on push to `next` only (not the 6-job matrix), ubuntu-24.04 / Node 24, cache-keyed by pin. Timeout 30 min.
- [  ] Cursor never writes to `realworld-approved.txt`. A test asserts the script only reads it.

Acceptance: a fixture "realworld" repo plus a fixture rule change produces one added key and exit 1; the same key in the approved file exits 0.

### Phase 78 — Cold-scan performance v2 [`FULLSHIELD_EXPERIMENTAL_PERF2`]
Target: Next.js sample cold p50 ≤ 60 s, nest and undici `--changed` p50 ≤ 5 s, peak RSS ≤ 1.5 GB, on the Phase 42 harness and machine. Output byte-identical (sorted JSON) with the flag on and off on every bench app and every realworld repo. Accuracy is never traded for speed; if the target needs that, stop and report (S3).

Build, in this order, measuring after each step and storing every run in `bench/perf-v2.json`:
1. [  ] **Profile first.** `node --cpu-prof` on the Next.js sample. Commit the top-20 self-time table to `bench/perf-v2-profile.md` before changing code. Each later step names which profile row it targets.
2. [  ] **Skip what cannot be source.** Before parsing: skip files over `scan.maxFileBytes` (default 1 MB) with an `info` note (not a finding), skip minified files (avg line length > 500 or one-line > 50 KB), skip `*.d.ts`, `*.map`, `dist/`, `build/`, `.next/`, `coverage/`, `out/` unless the user includes them. Skipped counts appear in `scan --json` `meta.skipped` **only with the flag on**.
3. [  ] **Parse once, share everywhere.** One AST per file shared by SAST, secrets context, reachability, and route map. Assert with a counter test that each file is parsed at most once per scan.
4. [  ] **Module-level parallelism.** deps (OSV, cache-first), secrets (regex, no AST), config, and SAST run concurrently; SAST parse stays on the Phase 42 worker pool. Deterministic merge order (sort by module, then key).
5. [  ] **Persistent call-graph cache.** Reachability import/call graph cached per file by content hash + version + config hash under the parse cache dir. Corrupt entry → discard (same contract as Phase 65).
6. [  ] **Lazy taint.** Run interprocedural taint only from files that contain a recognized source or are imported (depth ≤ 5) by a file that does; a file with no path to a source is not walked. Must be byte-identical; prove with the identical-output test.

Acceptance: identical-output test on all apps; cache-invalidation test; `bench/perf-v2.json` before/after on the same machine. If any target is still unmet, Section 28 is updated with the stored numbers. Section 38 point 4 changes only from a stored run.

### Phase 79 — Time budget and partial results [`FULLSHIELD_EXPERIMENTAL_BUDGET`]
CI users need a predictable upper bound.

- [  ] `scan --max-time <seconds>`: when the budget is reached, finish the current file, stop SAST taint expansion, still run deps/secrets/config to completion, and mark output `meta.incomplete: true` with `meta.incompleteModules`.
- [  ] Exit code 3 for "incomplete, no findings at or above --fail-on in what was scanned". A finding at or above `--fail-on` still exits 1. Documented in `docs/errors.md`.
- [  ] Console prints one yellow line: "Scan stopped at budget. N files not taint-checked."
- [  ] Never reports an incomplete scan as clean.

Acceptance: a fixture with a slow fake rule and `--max-time 1` exits 3 with `incomplete: true`; with a high finding in the scanned part exits 1; without the flag, output and exit codes are unchanged.

### Phase 80 — Type-aware receiver resolution [`FULLSHIELD_EXPERIMENTAL_TYPES`]
Most remaining SAST false positives are receiver guesses (is `db.query` a SQL client? is `x.find` Mongo or an array?). Use the TypeScript checker when the project has it.

- [  ] `typescript` is an optional peer, lazy-loaded only with the flag. Missing → `FS-E` with install hint; scan continues on the existing heuristics (no crash, no silent change).
- [  ] Build a `ts.Program` from the project's `tsconfig.json` (or `jsconfig.json`, or an inferred one with `allowJs`, `checkJs: false`). Memory cap: if the program exceeds `types.maxFiles` (default 5 000), fall back to heuristics and print one `info` line.
- [  ] Resolve receiver types for sink calls used by NoSQL, SQL, command, path, SSRF, and XSS rules. Resolved type matches a known sink type (from Phase 81 model packs) → keep; resolves to a non-sink type (e.g. `Array`, `Map`, a user class without a sink base) → suppress with `suppressedBy: "types"` in JSON (finding listed under `suppressed[]`, not deleted, only with the flag on); unresolved/`any` → existing behavior.
- [  ] Never adds a finding that the heuristic would not; this phase only removes. (Adding is a later, separate phase.)

Acceptance: fixtures — `items.find({ name: req.query.n })` on an array is suppressed; the same on a Mongoose model is kept; `any`-typed receiver keeps current behavior. clean-app 0. Report the per-app removed keys on tuning apps (labeled `seen`, unreviewed).

### Phase 81 — Library model packs [`FULLSHIELD_EXPERIMENTAL_MODELS`]
Ship source/sink/sanitizer knowledge as data, not code, using the Phase 64 schema.

- [  ] `models/<package>.json` for: express, express-validator, joi, yup, zod, validator, dompurify, sanitize-html, helmet, pg, mysql2, sqlite3, better-sqlite3, knex, sequelize, typeorm, prisma, mongoose, mongodb, child_process, execa, axios, node-fetch, undici, got, fs, fs-extra, path, ejs, pug, handlebars, nunjucks, jsonwebtoken, bcrypt.
- [  ] Each entry names: package, version range it was written against, kind (`source` / `sink` / `sanitizer` / `validator`), sink class, member path, argument index, and a one-line reference to the public API doc. No code copied from the libraries.
- [  ] A pack applies only when the package is in the project's dependency graph at a matching version range. Out-of-range → pack skipped with one `info` line.
- [  ] Packs are versioned with FullShield; a schema test validates every pack; a fixture test per pack (one positive, one negative).

Acceptance: with the flag on, `express-validator` `body('id').isInt()` before `db.query(... req.body.id ...)` suppresses the SQL finding (`suppressedBy: "model:express-validator"`); `.trim()` alone does not. Output identical with the flag off.

### Phase 82 — Secret precision: offline structure checks [`FULLSHIELD_EXPERIMENTAL_SECRET_CHECK`]
Cut secret false positives with no network call.

- [  ] Checksum validation only for token formats whose checksum is publicly documented by the issuer (GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_` CRC32 suffix; npm `npm_` tokens if and only if the format doc is cited in the rule file). Others: no checksum logic. Cite the doc URL in `rules/<ID>.md`.
- [  ] Failed checksum → `confidence: low` and `secretCheck: "checksum-failed"`. Never raises severity. Never deletes the finding.
- [  ] Placeholder filter: values that are all one char, sequential, contain `example`, `sample`, `dummy`, `changeme`, `your_`, `xxxx`, `<...>`, `${...}`, or match the documented AWS example key → `confidence: low`, `secretCheck: "placeholder"`.
- [  ] Context: files under `test/`, `__tests__/`, `fixtures/`, `*.test.*`, `*.spec.*`, `*.example`, `*.sample` → `confidence` lowered one step, `context: "test"`.
- [  ] With Phase 47 D3, low-confidence secrets below high severity drop out of the console view (JSON keeps them).

Acceptance: a valid-format fixture token (generated in the test with the documented algorithm, never a real token) passes; a one-char-off token fails; placeholder fixtures are low; output identical with the flag off.

### Phase 83 — External findings ingest and dedupe [`FULLSHIELD_EXPERIMENTAL_INGEST`]
Section 38 says use FullShield beside Semgrep, npm audit, and OSV-Scanner. Make that one command.

- [x] `fullshield ingest <file...>` reads local files only: SARIF 2.1.0 (any tool), OSV-Scanner `--format json`, `npm audit --json`, Semgrep `--json`. Never runs those tools. Never fetches.
- [x] Normalizes each to the Finding model with `source: "<tool>"`, keeps the tool's original rule ID in `externalRuleId`, never rewrites its severity.
- [x] Dedupe keys: dependency findings by `(advisoryId or alias, package, version)`; code findings by `(cwe, file, line ±3)` or SARIF `partialFingerprints` when present. Merged rows list every `sources[]`.
- [x] Annotates every ingested finding with FullShield's own evidence where it has it: dependency reachability class (Phase 39/61), route exposure and auth (Phase 58/75), sink class. Never changes the external tool's severity; adds `fullshieldPriority` only with Phase 84's flag.
- [x] Output: console (Phase 47 view), `--json`, `--sarif` (one run per source tool + one FullShield run, so GitHub keeps tool identity).
- [x] Malformed input → `FS-E` code naming the file and the first schema error; other files still ingested.

Acceptance: fixture outputs from each tool (hand-written, small, schema-valid) dedupe as expected: a CVE reported by npm audit and OSV-Scanner becomes one row with two sources; a Semgrep SQLi on the same line as `SAST-SQLI-001` becomes one row. Default scan unchanged.

### Phase 84 — Deterministic priority score [`FULLSHIELD_EXPERIMENTAL_PRIORITY`]
Sort by what to fix first, not only by severity.

- [  ] `priority` 0–100, computed from a documented table in `docs/priority.md`: severity, confidence, reachability class, route exposure (unauthenticated route reaches the sink → up; dev-only dependency → down), sink class, number of agreeing sources (Phase 83), KEV/EPSS only if Phase 56 exists and data is cached.
- [  ] Pure function, no ML, no network. Same input → same score (property test).
- [  ] `DEPS-MALICIOUS-001`, `SUPPLY-SECHOLDER-001`, `SUPPLY-STEALER-001` are always 100.
- [  ] Console sorts by priority, then severity, then file. JSON adds `priority` and `priorityFactors[]` only with the flag. Severity is never changed by priority.

Acceptance: table-driven test for every factor; ordering test on vulnerable-app; JSON identical with the flag off.

### Phase 85 — Attack paths [`FULLSHIELD_EXPERIMENTAL_PATHS`]
Join existing findings into the chain an attacker would use. No new rule IDs (no stable-output change).

- [  ] `scan --paths` adds a `paths[]` section: entry route (method, path, auth state from Phase 58/75) → trace steps (existing `trace`) → sink finding; plus dependency chains: route → call into a `reachable` vulnerable dependency symbol (Phase 61 evidence).
- [  ] Secret chains: a hardcoded secret finding whose identifier is used in reachable code (same module graph) is linked to the sink or client that consumes it.
- [  ] Each path lists only findings that already exist; a path never creates a finding and never raises severity.
- [  ] Console: top 5 paths by the highest priority in the path (Phase 84 if on, else severity). `report` HTML gets a Paths tab.

Acceptance: vulnerable-app fixture with an unauthenticated route → SQL sink produces one path; adding router-level auth (Phase 75 fixture) marks the path `auth: present`. No path appears on clean-app.

### Phase 86 — Dependency capability profile and diff [`FULLSHIELD_EXPERIMENTAL_CAPABILITIES`]
The MALFEX packages looked like small helpers but used process spawning and network on install. Show what each dependency can do.

- [  ] Static read of already-installed package files in `node_modules` (never execute, never install, R15). For each package version: `child_process`, `net`/`http(s)`/`dgram`/`fetch`, `fs` write APIs, `process.env` reads, `eval`/`new Function`/`vm`, native addon (`.node`, `binding.gyp`), dynamic `require` of a computed string, install scripts (`preinstall`/`install`/`postinstall`), and obfuscation signals (long hex/base64 blobs, `\x` density) — reusing Phase 70 heuristics where they exist.
- [  ] `fullshield deps --capabilities` prints per direct dependency the union of its own and transitive capabilities, with the package that introduces each one.
- [  ] `deps-diff` (Phase 62) with the flag adds "new capabilities introduced by this change", e.g. a patch bump that adds `child_process` + `postinstall`.
- [  ] Policy: `deps.capabilityPolicy` in config (`deny` / `warn` per capability per package glob). A `deny` hit produces `SUPPLY-CAP-001` (new rule ID, experimental only, never in default scan).
- [  ] Results cached by package integrity hash.

Acceptance: fixture `node_modules` with an inert package that has a `postinstall` and a `child_process` import is listed with both, attributed correctly through a transitive path; a version bump fixture that adds `net` appears in deps-diff; no child process is spawned during the scan (test spies `child_process`).

### Phase 87 — Provenance and maintainer change signals [`FULLSHIELD_EXPERIMENTAL_PROVENANCE`]
Uses `registry.npmjs.org` only (R15 allowed). Cache-first; `--offline` uses cache only; missing data stays `unknown`, never guessed.

- [x] For each installed version: whether the registry lists a provenance attestation (`dist.attestations`), and the publishing user for that version.
- [x] Signals (informational, `SUPPLY-PROV-001` experimental): (a) **provenance regression** — earlier versions of the same package had provenance and the installed version does not; (b) **publisher change** — the installed version was published by a user who published none of the previous N (default 10) versions; (c) **new-release** — reuse Phase 62's age check.
- [x] Never claims a package is malicious from these signals. Severity `medium` at most; `DEPS-MALICIOUS-001` still only from OSV `MAL-` advisories.
- [x] Request concurrency ≤ 8, respects `Retry-After`, one request per package (packument), shared with Phase 62's registry cache.

Acceptance: mocked registry fixtures for each signal; a test asserts only `registry.npmjs.org` is contacted; `--offline` with an empty cache produces `unknown`, not a signal.

### Phase 88 — Developer loop: `fullshield dev` [`FULLSHIELD_EXPERIMENTAL_DEV`]
Feedback while coding, without an editor extension (Section 31).

- [x] `fullshield dev` watches the project with `fs.watch` (recursive where supported; polling fallback on Linux without recursive support, interval configurable). Debounce 300 ms.
- [x] On change: rescan only changed files and their reverse dependents (Phase 42 `--changed` logic + Phase 78 caches). Print only **new** and **resolved** findings since the previous run, using the Section 34 line-independent key.
- [x] Never runs deps OSV lookups on every save; deps rescan only when a manifest or lockfile changes.
- [x] Ctrl-C closes watchers and every DB handle (Windows, R22).

Acceptance: a test edits a fixture file to add a SQLi and asserts one "new" line within 5 s, then reverts and asserts one "resolved" line. Runs on Linux/macOS/Windows CI (or `skipIf` with reason).

### Phase 89 — SPDX SBOM [`FULLSHIELD_EXPERIMENTAL_SPDX`]
- [  ] `fullshield sbom --format spdx` emits SPDX 2.3 JSON: packages with PURL external refs, `DEPENDS_ON` relationships from the lockfile graph, license only when present in package data (never invented, Section 17).
- [  ] Vulnerability data stays in CycloneDX/VEX (SPDX 2.3 has no native vuln section); the SPDX doc references the CycloneDX file if generated in the same run.
- [  ] Validation against the SPDX 2.3 JSON schema, vendored under `test/schemas/` (not shipped).

Acceptance: schema validation passes on vulnerable-app and one bench app; deterministic output (sorted, fixed `created` timestamp via `--sbom-timestamp` or `SOURCE_DATE_EPOCH`).

### Phase 90 — User-supplied Semgrep-style rules (subset) [`FULLSHIELD_EXPERIMENTAL_SEMGREP_RULES`]
Lets teams reuse rules they already wrote. FullShield never bundles or downloads third-party registry rules (license and R15).

- [  ] Reads user-provided YAML (optional peer `yaml`, lazy) and compiles a documented subset into the Phase 57 schema: `languages: [javascript, typescript]`, `pattern`, `pattern-either`, `pattern-not`, `pattern-inside`, metavariables `$X`, `...` in arguments, and `mode: taint` with `pattern-sources` / `pattern-sinks` / `pattern-sanitizers` mapped to the existing taint engine.
- [  ] Any unsupported construct → the rule is rejected (fail closed) with `FS-E` listing the construct and the rule id. Never partially applied.
- [  ] `docs/semgrep-subset.md` lists exactly what is supported and states that results may differ from Semgrep.
- [  ] Findings carry `ruleId: "CUSTOM-<user id>"` and `source: "user-rule"`.

Acceptance: 10 hand-written rules (from scratch, B8) covering every supported construct each have a positive and negative fixture; 3 rules with unsupported constructs are rejected with the right message; flag off → rules file not even parsed.

### Phase 91 — Fix verification [`FULLSHIELD_EXPERIMENTAL_FIX_VERIFY`]
Every proposed fix proves it removes its finding and adds none. Never executes project code (R15).

- [  ] For each `fix` patch (Section 8) and each `explain` (Phase 60) suggested change: apply in memory, re-run the affected rules on the patched file and its direct importers, and record `verified: "removes-finding" | "does-not-remove" | "introduces-finding"`.
- [  ] Patches that `introduces-finding` are never written, even with `--yes`. `does-not-remove` patches are shown with a warning and require `--force-unverified`.
- [  ] Dependency fixes (overrides, Phase 31/49) are verified by re-resolving the advisory set against the planned versions using OSV cache; never by running `npm install`.

Acceptance: fixture fix that works → `removes-finding`; a deliberately wrong fixture patch → `does-not-remove`; a patch that adds `eval` → `introduces-finding` and is not written.

### Phase 92 — Repository hygiene (docs and templates)
- [ X ] `.github/ISSUE_TEMPLATE/false-positive.yml` (rule ID, minimal code, version, expected), `false-negative.yml`, `bug.yml`, `config.yml` (blank issues off, link to SECURITY.md for vulnerabilities).
- [ X ] `docs/use-with-other-tools.md`: concrete commands to run Semgrep, OSV-Scanner, npm audit, Gitleaks next to FullShield and then `fullshield ingest` (Phase 83). No claims about other tools' accuracy.
- [ X ] `docs/branch-protection.md`: the exact required check names from the 6-job matrix, for the human to set (R1). Cursor does not change repo settings.
- [ X ] Closes the Section 33 issue-templates item.

Acceptance: YAML templates validate against GitHub's issue-form schema (vendored, test-only); doc links resolve (link-check test on local paths).

### Phase 93 — Promotion evidence batch 2 (process, no promotion)
Run the Phase 73 report for: `_VALIDATION` (53), `_WORKSPACES` (54), `_OBSERVED_REACH` (55), `_CUSTOM_RULES` (57), `_ROUTES` (58), `_EXPLAIN` (60), `_REACH_EVIDENCE` (61), `_DEPS_DIFF` (62), `_LOCKFILES` (63), `_CUSTOM_SANITIZERS` (64), `_SBOM_REACH` (66), `_SARIF_V2` (74), and every flag from Phases 78–91 that is merged.

- [x] One `bench/promotion/<flag>.md` per flag, same columns as Phase 73.
- [x] `bench/promotion/SUMMARY.md`: flag | criteria met | criteria unmet | default-scan-diff if promoted (EMPTY / count).
- [x] Cursor promotes nothing (R1, R11).

---

## 40. Today's Cursor Work Order (2026-10-19, full day)

Replaces Section 36 as the queue. Section 36 stays as the 2026-10-18 record. Section 0 wins over this section (S7).

### 40.1 Start of day (once)
0. **Spec check.** The first line of this file must read `rev 2026-10-19e` (or later). If it does not, stop and tell the human the file was not replaced. Never reconstruct this spec from chat text.
0a. **Snapshot currency.** `bench/snapshots/HEAD.json` must be the default-scan snapshot of the version `npm view fullshield dist-tags.latest` returns (R9). If it is older, report the drift keys and wait for the human's approval line naming the exact keys before regenerating it. After approval: regenerate from the release commit of that version, commit as `snapshot: HEAD = <version>`, and quote the approval line in the commit body.
1. `git switch next && git pull`. `npm run verify` on the untouched tree; paste the summary table. Red → stop (S4).
2. `node scripts/default-scan-diff.mjs` against `bench/snapshots/HEAD.json` must be empty.
3. One worktree per item (R21): `git worktree add ../fs-<N> -b phase-<N> next`.

### 40.2 Lanes
Lane A is the priority. B and C run only while A waits on the human or after A is done. Realistic expectation: Lane A plus 3–5 Lane C items in one day. Unfinished items stay on their branch and are reported (S3); do not rush acceptance.

**Lane A — finish what blocks a release (sequential):**

| Order | Item | Stable change? | Gate |
|---|---|---|---|
| A1 | 75, 50, 51, 52: produce `bench/snapshots/DIFF.txt` on each `phase-N` branch if not already there | **Yes (R10)** | Report under 0.8 with "Needs human decision: approve stable diff". Do not merge. |
| A2 | 78 Cold-scan performance v2 (steps 1–6 in order, measure after each) | No (byte-identical) | identical-output test on all apps + `bench/perf-v2.json` |
| A3 | 65 re-measure nest/undici with 78 on; update Section 28 from the stored run | No | stored numbers only |

**Lane B — evidence tooling (dev only, not in tarball):**

| Order | Phase |
|---|---|
| B1 | 76 Precision sampling harness |
| B2 | 77 Real-world precision regression gate |
| B3 | 92 Repository hygiene |
| B4 | 93 Promotion evidence batch 2 (run last, after merges) |

**Lane C — experimental features (one flag each; merge one at a time after verify + empty default-scan-diff):**

| Order | Phase | Flag |
|---|---|---|
| C1 | 82 Secret structure checks | `FULLSHIELD_EXPERIMENTAL_SECRET_CHECK` |
| C2 | 81 Library model packs | `FULLSHIELD_EXPERIMENTAL_MODELS` |
| C3 | 80 Type-aware receivers | `FULLSHIELD_EXPERIMENTAL_TYPES` |
| C4 | 84 Priority score | `FULLSHIELD_EXPERIMENTAL_PRIORITY` |
| C5 | 83 Ingest and dedupe | `FULLSHIELD_EXPERIMENTAL_INGEST` |
| C6 | 86 Capability profile | `FULLSHIELD_EXPERIMENTAL_CAPABILITIES` |
| C7 | 87 Provenance signals | `FULLSHIELD_EXPERIMENTAL_PROVENANCE` |
| C8 | 85 Attack paths | `FULLSHIELD_EXPERIMENTAL_PATHS` |
| C9 | 79 Time budget | `FULLSHIELD_EXPERIMENTAL_BUDGET` |
| C10 | 88 `fullshield dev` | `FULLSHIELD_EXPERIMENTAL_DEV` |
| C11 | 91 Fix verification | `FULLSHIELD_EXPERIMENTAL_FIX_VERIFY` |
| C12 | 89 SPDX SBOM | `FULLSHIELD_EXPERIMENTAL_SPDX` |
| C13 | 90 Semgrep-style rules | `FULLSHIELD_EXPERIMENTAL_SEMGREP_RULES` |

Dependencies: 84 before 85 (85 sorts by priority if on). 81 before 80 (80 uses pack sink types). 62 already merged before 86/87.

Not today: 53–55, 57–59 are done; 56 stays blocked on R15.

### 40.3 Hard stops for today
- [  ] Lane A1 items: stop that phase at the diff (R10), park it, continue the queue.
- [  ] Any test / fixture / `expected-findings.json` / `ground-truth.json` / `triage.json` / `realworld-approved.txt` / `bench/precision/*` label edit needed: stop (S2).
- [  ] Coverage within 2 points of a threshold: stop (S5).
- [  ] Phase 78 cannot reach a target without changing output: stop and report numbers (S3).
- [  ] No tag, no publish, no push to `main`. Version on `next` bumps to the next minor only if R16 requires it, and the human picks the number.
- [  ] Never set `"reviewed": true`; never fill `label`, `reviewer`, `note`.

### 40.4 End of day
Same as Section 36.4, plus: `bench/perf-v2.json` p50 table (before/after) and, if Phase 76 is merged, the count of rows waiting for human labels per app. All of it goes into the report file (Section 40.5), not only the chat.

### 40.5 Run to completion and the report file
1. **Work the whole queue.** Go through Lane A, then B, then C, in order, without waiting for the human between items. A stop condition parks only that phase (R23). Do not ask "should I continue?" The answer is always yes unless R23 lists the condition as a session stop.
2. **Report file.** At the start of the day, create `reports/2026-10-19.md` on `next` (create the `reports/` folder if needed; add `reports/` to `.npmignore` / the `files` allowlist exclusion, and confirm `pack-budget` still passes). Commit it as `report: 2026-10-19 start`.
3. **Append after every phase**, whether finished, parked, or failed, and commit right away as `report: phase-N`. Each entry has:
   - the full 0.8 block for that phase,
   - `Status: merged into next | parked (reason + stop code) | not started (why)`,
   - real command output: the `verify` summary table and every failure in full (R8). No summaries of failures.
4. **Top of the file** is a live summary table kept up to date: `phase | lane | status | branch | sha | flag | tests added | default-scan-diff | needs human`.
5. **Resume rule.** If the chat ends, runs out of context, or is restarted, the first action of the new chat is: read Section 0, Section 39.1, Section 40, and `reports/2026-10-19.md`, then continue with the first item whose status is not `merged` or `parked`. Never redo a merged item.
6. **End of day.** Append the Section 40.4 block under `## End of day` and commit as `report: 2026-10-19 end`. Push `next` (pushing `next` is allowed; `main` is not). The human pastes this file into the review chat.
7. The report file is the record. Numbers in it follow R6–R8: real output only, `unreviewed` where it applies, nothing invented.

---

## 41. Human-only work that decides market position (Cursor cannot do these)
Features do not make the package lead its area; measured, reviewed numbers and releases do. These are blocked on the human (R1):

1. [  ] Review ground truth for the tuning apps with the Phase 67 CLI (`reviewed: true` is human-only).
2. [  ] Label the Phase 76 precision samples (about 10 per rule per app).
3. [  ] Approve or reject the R10 diffs for Phases 75, 50, 51, 52.
4. [  ] Set branch protection to the 6 required checks (`docs/branch-protection.md`), and confirm the full matrix ran green on `main`.
5. [  ] Decide on R15 for Phase 56 (EPSS / KEV hosts): amend or keep blocked.
6. [  ] Decide promotions from `bench/promotion/SUMMARY.md` (Phase 43 criteria).
7. [  ] Pick the next release number (expected minor, R16) and run Section 2 with provenance (S6).
8. [  ] After 1–2: publish per-rule precision with n and interval in BENCHMARK.md, labeled reviewed. That table, not a feature list, is the credible public claim.

---

## 42. Quality Gate (R24) and Phase 94

**R24. Quality gate.** From Phase 94 on, `npm run verify` includes `npm run quality`. A phase whose branch fails `quality` cannot merge into `next`. The checks only tighten (ratchet); loosening any of them is an R1 threshold change.

### Phase 94 — Quality gate (dev tooling, run BEFORE the wip split)
All tools are `devDependencies` only (R13 covers runtime deps; nothing here ships in the tarball). Build `scripts/quality.mjs`, which runs Q1–Q12 and prints one table: `check | scope | result | count | baseline`.

| ID | Check | Scope | Fails when |
|---|---|---|---|
| Q1 | ESLint as errors: `eqeqeq`, `no-var`, `prefer-const`, `curly`, `no-throw-literal`, `default-case-last`, `no-implicit-coercion`, `@typescript-eslint/no-explicit-any`, `@typescript-eslint/no-floating-promises`, `@typescript-eslint/no-misused-promises`, `@typescript-eslint/switch-exhaustiveness-check`, `complexity: 15`, `max-depth: 4`, `max-params: 5`, `max-lines-per-function: 80` | files changed vs `next` (`git diff --name-only next...HEAD -- src`) | any violation in a changed file |
| Q2 | Same rules, whole `src/` | whole repo | count rises above `quality/baseline.json` (ratchet; record today's count, never raise it) |
| Q3 | `eslint-disable` lines | whole repo | a disable without `-- reason`, or total disables rise above baseline. Each one listed in `docs/DECISIONS.md` |
| Q4 | Dead code (`knip`) | whole repo | an unused export, file, or devDependency introduced by the branch. Public exports in `package.json#exports` are kept |
| Q5 | Public API snapshot `api/fullshield.api.json`: exported names and `.d.ts` text (comments stripped) for every `exports` entry, `fullshield --help` and every subcommand `--help`, the `FS-E` code list, the rule ID list, the experimental flag list | whole package | differs from the committed file. Updating it is allowed only in the phase that adds the API, and that phase's report lists the diff (R16 minor bump) |
| Q6 | Error codes: every `throw` / CLI failure in `src/` uses `FullShieldError` with an `FS-E###` code documented in `docs/errors.md` | whole repo | an undocumented code, or a new bare `throw new Error` |
| Q7 | Dangerous APIs: `child_process`, `eval`, `new Function`, `vm`, dynamic `require(<non-literal>)`, `process.binding` | `src/` | any use not in `quality/allowed-dangerous.json` (path + API + reason; existing fix-engine/git uses go there today). Runtime entry points (`src/runtime*`) allow none |
| Q8 | Network hosts: every `fetch`/`http(s).request`/`undici` call site resolves to an allowlisted host constant in `src/net/hosts.ts` (OSV, registry.npmjs.org, localhost, user-configured; EPSS/KEV only if Phase 56 is approved) | `src/` | a literal URL or host outside that file |
| Q9 | Per-file coverage for files **added** by the branch: lines ≥ 90%, branches ≥ 80% | new files | below either. Global thresholds are unchanged (R1) |
| Q10 | Mutation smoke: every new rule ID and every new suppression path has a mutant that the tests kill | new rules | a surviving mutant |
| Q11 | Determinism: default `scan --json` run twice on vulnerable-app and one bench app, sorted, byte-identical; same with every new flag on | — | any byte difference |
| Q12 | Pack: `npm pack --dry-run` file list matches `quality/pack-files.txt`; no `test/`, `bench/`, `reports/`, `scripts/` (except shipped ones), `.map`; `pack-budget` passes | tarball | an unexpected file |

Also in Phase 94:
- [ X ] `docs/QUALITY.md`: one page listing Q1–Q12, what each enforces, and today's numbers. Linked from README.
- [  ] `quality/baseline.json` is generated once in this phase from `next`, committed, and is human-owned afterwards (Cursor may lower counts, never raise them).
- [  ] No refactor of existing code in this phase. Existing violations are recorded in the baseline, not fixed. Behavior must not change: default-scan-diff EMPTY.

Acceptance: `npm run quality` passes on `next`; a fixture branch with an `any`, an undocumented `FS-E`, a literal `https://example.com` fetch, and an unused export fails with four named rows.

### 42.1 Definition of done for every remaining phase (applies to 50, 51, 52, 56, 65, 76–93)
A phase is `merged` only when ALL of these are in its report with raw output:
1. [  ] Acceptance section of the phase met item by item (checklist copied into the report, each line `met` / `not met` with evidence).
2. [  ] Tests: failing first (R4), then green; ≥ 1 positive and ≥ 1 negative per rule / suppression / signal; total test count before → after.
3. [  ] `npm run verify` (incl. `quality` after Phase 94) summary table, all green.
4. [  ] `default-scan-diff`: EMPTY, or the phase is parked with `DIFF.txt` (R10).
5. [  ] Flag-off identical test, and clean-app 0 with flag on (R12).
6. [  ] Docs in the same commit: `rules/<ID>.md` for new rules, README flag table row, CHANGELOG under Unreleased, Section 28 if a limit remains, `docs/errors.md` for new codes, `api/fullshield.api.json` diff listed.
7. [  ] "False-positive risk" paragraph: which real code could trigger this wrongly, and what the negative fixture covers.
8. [  ] Branch pushed (phase branch and `next`; never `main`).

A phase that cannot meet 1–8 is `parked` with the failing item named. "Coded" is not a status.

---

## 43. Finish-All Run (supersedes the Section 40.2 order; Section 40.5 report rules still apply)

**R25. One queue only.** This section is the only work queue. `docs/history/RUN-PROMPT.md`, `PROGRESS.md`, `docs/history/RUN-LOG.md`, `.cursor/rules/*`, `AGENTS.md`, and any other file may record history but may not define a queue, batches, or a stop point. Any batch list or "stop after this batch" text in those files is void. At Stage 0, replace the body of `docs/history/RUN-PROMPT.md` with one line: `Superseded. The only queue is SECURITY_SCANNER_SPEC.md Section 43.` and remove any stop/batch instructions from `.cursor/rules/*` and `AGENTS.md` if present (commit `docs: retire old run prompt (R25)`). Phases already marked [X] in this spec are never redone.

Report file: keep appending to `reports/2026-10-19.md`; after midnight local time start `reports/2026-10-20.md` with the same summary table carried over.

| Stage | Items | Notes |
|---|---|---|
| 0 | Safety | `git status` on every worktree. Commit any uncommitted work on its own branch as `wip: <phase> checkpoint`; push all `phase-*`, `wip/*`, and `next`. Paste `git branch -vv`. |
| 1 | 75, 51 (D9), 50 (D10), 52 rework (D11) | Per the human decisions of 2026-10-19 in the report file. 52 ends parked for approval. |
| 2 | 94 Quality gate | Before any further merge. |
| 3 | 78 steps 3–6, then 65 re-measure | `bench/perf-v2.json` after each step, 3 runs, p50, no `--cpu-prof`. |
| 4 | Split `wip/2026-10-19-bulk` in this order: 76, 82, 81 (single generated `models/index.json`), 80, 84, 83, 86, 87, 85, 79, 91, 89, 92 | The wip code is a draft, not trusted. Re-read each phase's Section 39 text, write the missing tests first, then fix the code until 42.1 is met. Do not copy wip's edit to `test/fixtures/clean-app/package.json` (R3; only D11 may change it). |
| 5 | 77, 88, 90 | New work. |
| 6 | 56 | Only if the human's current message contains the line `R15 AMENDED FOR PHASE 56`. Otherwise skip, status `blocked (R15)`. |
| 7 | 93 promotion evidence, Section 30 update, end-of-day block (40.4) | Last. |

Parallelism: Stage 4 and 5 items may be built in parallel worktrees (R21) after Stage 2 is merged. Merge into `next` strictly in the table order, one at a time, verify + diff after each. A parked item never blocks a later item that does not import its code.

### 43.1 Phase 56 under the R15 amendment (only if approved)
If approved, R15 additionally allows, **only** with `--exploit-intel` or `FULLSHIELD_EXPERIMENTAL_EXPLOIT_INTEL=1`: `GET https://api.first.org/data/v1/epss` (query by CVE, batch ≤ 100) and `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. Default scan never contacts them (test asserts). Cache 24 h next to the OSV cache; `--offline` uses cache only; missing data leaves fields unset. Hosts are added to `src/net/hosts.ts` (Q8) and README "Network" section in the same commit. Then build Phase 56 exactly as Section 32 specifies.

---

## 44. 1.0.1 Docs Release (2026-10-20)

Docs-only. No change under `src/`, `rules/*.md` detection text, `test/fixtures/`, or `bench/*/ground-truth.json`. `default-scan-diff` must be EMPTY. `semver-check` must say `patch` under R16a.

1. Replace `docs/stability.md` (contract correction).
2. CHANGELOG `1.0.1` entry.
3. Rewrite `CAPABILITIES.md`; no hand-written counts.
4. Fix stale lines in `docs/errors.md`, `docs/QUALITY.md`, `docs/priority.md`, `docs/NOISE-REPORT.md`, `CONTRIBUTING.md`.
5. Move history docs to `docs/history/`: `ADVANCED-SPEC.md`, `PARKED.md`, `RUN-LOG.md`, `RUN-PROMPT.md`, `STABILIZATION-PLAN.md`. Update every link to them.
6. Regenerate `docs/demo.md`, `BENCHMARK.md` from real runs at 1.0.1. Banner `COMPARISON.md` as not citable.
7. Mark experimental exports in `api/fullshield.api.json` (Q5 snapshot) without changing any export.
8. Dev-only: `scripts/doc-version-check.mjs` fails when a doc names a FullShield version as current that is not `package.json` `version`. Wired into `npm run verify`. Not packed.
9. PR `next` → `main`. Six required checks green. Human sets branch protection. Human tags `v1.0.1`.

Done. Pull request #18 merged as `dc2b719`. Tag `v1.0.1` is that commit. The six checks are required on `main`. npm published `1.0.1` at 2026-10-21T02:43:27Z with provenance: https://github.com/kathanp/fullshield/actions/runs/39529799316

---

## 45. Autopilot runs (R26)

**R26. AUTOPILOT runs.** A version may be built by the local AUTOPILOT.md playbook with
scripts/autopilot/guard.mjs. For such a run only:

1. Queue. The version scope the human writes into this SPEC for the run is the only queue
   (amends R25 for the run; Section 43 is history).
2. Branches. Work happens on a local run/<name> branch off `next`, with phase worktrees
   wk/test/phase-N and wk/code/phase-N in ../fullshield-wt/ (amends R18 and R21 for
   location only; integration is still one phase at a time, in table order, verify and
   default-scan-diff after each).
3. Commits. run/<name> keeps one `phase-N: <summary>` commit per phase (R19). The finished
   run is squashed into one commit `release: <x.y.z>` on release/<x.y.z>, which the human
   fast-forwards onto `next`; `main` still moves only by PR from `next` (R18). R19's
   "never mix phases in one commit" does not apply to that release commit.
4. Records. No report file, run log, or PROGRESS.md entry is written (replaces Section
   40.5 for the run). R8 still applies: real output is pasted in the chat summary.
5. Approval. A person approves this SPEC for the run with `guard.mjs --approve-spec`.
   After approval the SPEC is frozen for the run; a change needs a new approval.
6. Everything else in Section 0 applies unchanged, including R1, R3, R3a, R10, R11, R13,
   R15, R16a, R17, R22, R23, R24 and S1-S7.

### Version scope 1.2.0

This block is the only queue for the autopilot run (R26 item 1). Target `1.2.0`, a minor (R16a): every rule ID in Section 46 and Section 47 is new. Definitions stay in those sections. This run does not promote any rule (R11). Section 41 items 1–2 on NodeGoat and goof are not done, so nothing moves to stable and default `scan --json` output does not change (no R10). Phases 108–250 are in this version, after 107.

Order: 105 → 95 → 96 → 102 → 104 → 97 → 99 → 100 → 98 → 103 → 101 → 106 → 107, then 108 through 250 in numeric order.

| Phase | Flag | Stable-output change |
|---|---|---|
| 105 | `FULLSHIELD_EXPERIMENTAL_CREDFILES` | no |
| 95 | `FULLSHIELD_EXPERIMENTAL_TLS` | no |
| 96 | `FULLSHIELD_EXPERIMENTAL_CRYPTO2` | no |
| 102 | `FULLSHIELD_EXPERIMENTAL_ELECTRON` | no |
| 104 | `FULLSHIELD_EXPERIMENTAL_VENDORED` | no |
| 97 | `FULLSHIELD_EXPERIMENTAL_SSTI` | no |
| 99 | `FULLSHIELD_EXPERIMENTAL_WEBHOOK` | no |
| 100 | `FULLSHIELD_EXPERIMENTAL_SESSION2` | no |
| 98 | `FULLSHIELD_EXPERIMENTAL_LOGLEAK` | no |
| 103 | `FULLSHIELD_EXPERIMENTAL_NEXT` | no |
| 101 | `FULLSHIELD_EXPERIMENTAL_BROWSER` | no |
| 106 | `FULLSHIELD_EXPERIMENTAL_HEALTH` | no |
| 107 | `FULLSHIELD_EXPERIMENTAL_IDOR` | no |
| 108 | `FULLSHIELD_EXPERIMENTAL_NPM_SHRINKWRAP` | no |
| 109 | `FULLSHIELD_EXPERIMENTAL_NPM_LOCKVER` | no |
| 110 | `FULLSHIELD_EXPERIMENTAL_NPM_MULTLOCK` | no |
| 111 | `FULLSHIELD_EXPERIMENTAL_NPM_ROOTVER` | no |
| 112 | `FULLSHIELD_EXPERIMENTAL_NPM_NONSEMVER` | no |
| 113 | `FULLSHIELD_EXPERIMENTAL_NPM_NORESOLVED` | no |
| 114 | `FULLSHIELD_EXPERIMENTAL_NPM_RESOLVED_HOST` | no |
| 115 | `FULLSHIELD_EXPERIMENTAL_NPM_RESOLVED_HTTP` | no |
| 116 | `FULLSHIELD_EXPERIMENTAL_NPM_NOINTEGRITY` | no |
| 117 | `FULLSHIELD_EXPERIMENTAL_NPM_WEAKINTEGRITY` | no |
| 118 | `FULLSHIELD_EXPERIMENTAL_NPM_BADINTEGRITY` | no |
| 119 | `FULLSHIELD_EXPERIMENTAL_NPM_LINKDEP` | no |
| 120 | `FULLSHIELD_EXPERIMENTAL_NPM_GITDEP` | no |
| 121 | `FULLSHIELD_EXPERIMENTAL_NPM_ALIAS` | no |
| 122 | `FULLSHIELD_EXPERIMENTAL_NPM_BUNDLED` | no |
| 123 | `FULLSHIELD_EXPERIMENTAL_NPM_PEER` | no |
| 124 | `FULLSHIELD_EXPERIMENTAL_NPM_OPTIONAL` | no |
| 125 | `FULLSHIELD_EXPERIMENTAL_NPM_LOCKPATH` | no |
| 126 | `FULLSHIELD_EXPERIMENTAL_NPM_LOCKOMIT` | no |
| 127 | `FULLSHIELD_EXPERIMENTAL_NPM_DEVPROD` | no |
| 128 | `FULLSHIELD_EXPERIMENTAL_NPM_FLOAT` | no |
| 129 | `FULLSHIELD_EXPERIMENTAL_NPM_GITSPEC` | no |
| 130 | `FULLSHIELD_EXPERIMENTAL_NPM_FILESPEC` | no |
| 131 | `FULLSHIELD_EXPERIMENTAL_NPM_URLSPEC` | no |
| 132 | `FULLSHIELD_EXPERIMENTAL_NPM_TAGSPEC` | no |
| 133 | `FULLSHIELD_EXPERIMENTAL_NPM_OVERRIDE_VULN` | no |
| 134 | `FULLSHIELD_EXPERIMENTAL_NPM_OVERRIDE_WIDE` | no |
| 135 | `FULLSHIELD_EXPERIMENTAL_NPM_OVERRIDE_ALIAS` | no |
| 136 | `FULLSHIELD_EXPERIMENTAL_NPM_LIFECYCLE` | no |
| 137 | `FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_REG` | no |
| 138 | `FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_SCRIPT` | no |
| 139 | `FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_HOME` | no |
| 140 | `FULLSHIELD_EXPERIMENTAL_NPM_PACKAGEMANAGER` | no |
| 141 | `FULLSHIELD_EXPERIMENTAL_NPM_COREPACK` | no |
| 142 | `FULLSHIELD_EXPERIMENTAL_NPM_ENGINES` | no |
| 143 | `FULLSHIELD_EXPERIMENTAL_NPM_ENGINE_STRICT` | no |
| 144 | `FULLSHIELD_EXPERIMENTAL_NPM_TRUSTED` | no |
| 145 | `FULLSHIELD_EXPERIMENTAL_NPM_PUBLISHCONFIG` | no |
| 146 | `FULLSHIELD_EXPERIMENTAL_NPM_BINSHADOW` | no |
| 147 | `FULLSHIELD_EXPERIMENTAL_NPM_OSCPU` | no |
| 148 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_INTEGRITY` | no |
| 149 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_TARBALL` | no |
| 150 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_DEPRECATED` | no |
| 151 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_UNPUBLISHED` | no |
| 152 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_NPMUSER` | no |
| 153 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_MAINTAINER` | no |
| 154 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_PROV_ABSENT` | no |
| 155 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_BUILDER` | no |
| 156 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_REPO` | no |
| 157 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_SUBJECT` | no |
| 158 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_TIME` | no |
| 159 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_TRANSITIVE_AGE` | no |
| 160 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_INSTALLSCRIPT` | no |
| 161 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_SIGNATURES` | no |
| 162 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_ENGINES` | no |
| 163 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_DRIFT` | no |
| 164 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_DEPS` | no |
| 165 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_PEER` | no |
| 166 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_BIN` | no |
| 167 | `FULLSHIELD_EXPERIMENTAL_NPM_REG_REPOSITORY` | no |
| 168 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_HASH` | no |
| 169 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_ID` | no |
| 170 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_LIFECYCLE` | no |
| 171 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_NET` | no |
| 172 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_SHELL` | no |
| 173 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_CRED` | no |
| 174 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_OBFUSC` | no |
| 175 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_BIN` | no |
| 176 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_NATIVE` | no |
| 177 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_HOOK` | no |
| 178 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_HIDDEN` | no |
| 179 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_PATH` | no |
| 180 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_SIZE` | no |
| 181 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_LICENSE` | no |
| 182 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_MANIFEST` | no |
| 183 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_INSTALLJS` | no |
| 184 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_TOPLEVEL` | no |
| 185 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_ENV` | no |
| 186 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_DYNAMIC` | no |
| 187 | `FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_GATE` | no |
| 188 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_TRANSITIVE` | no |
| 189 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_OPTIONAL` | no |
| 190 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_DEV` | no |
| 191 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_PREPARE` | no |
| 192 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_PREPUBLISH` | no |
| 193 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_CURL` | no |
| 194 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_BASE64` | no |
| 195 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_NODEGYP` | no |
| 196 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_WRITE` | no |
| 197 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_LOCK` | no |
| 198 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_GIT` | no |
| 199 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_TOKEN` | no |
| 200 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_PUBLISH` | no |
| 201 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_TRUSTED` | no |
| 202 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_MISMATCH` | no |
| 203 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_MULTI` | no |
| 204 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_BIN` | no |
| 205 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_SHEBANG` | no |
| 206 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_COND` | no |
| 207 | `FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_ROLLUP` | no |
| 208 | `FULLSHIELD_EXPERIMENTAL_NPM_SCOPE_TYPO` | no |
| 209 | `FULLSHIELD_EXPERIMENTAL_NPM_HOMOGLYPH` | no |
| 210 | `FULLSHIELD_EXPERIMENTAL_NPM_BIDI` | no |
| 211 | `FULLSHIELD_EXPERIMENTAL_NPM_MIXEDSCRIPT` | no |
| 212 | `FULLSHIELD_EXPERIMENTAL_NPM_SEPARATOR` | no |
| 213 | `FULLSHIELD_EXPERIMENTAL_NPM_REPEAT` | no |
| 214 | `FULLSHIELD_EXPERIMENTAL_NPM_SUFFIX` | no |
| 215 | `FULLSHIELD_EXPERIMENTAL_NPM_SCOPE_NEW` | no |
| 216 | `FULLSHIELD_EXPERIMENTAL_NPM_SCOPE_SYNTAX` | no |
| 217 | `FULLSHIELD_EXPERIMENTAL_NPM_TYPES` | no |
| 218 | `FULLSHIELD_EXPERIMENTAL_NPM_DEPRECATED_REPLACE` | no |
| 219 | `FULLSHIELD_EXPERIMENTAL_NPM_TYPO_TRANSITIVE` | no |
| 220 | `FULLSHIELD_EXPERIMENTAL_NPM_NAME_LENGTH` | no |
| 221 | `FULLSHIELD_EXPERIMENTAL_NPM_NAME_CASE` | no |
| 222 | `FULLSHIELD_EXPERIMENTAL_NPM_NAME_ENCODED` | no |
| 223 | `FULLSHIELD_EXPERIMENTAL_NPM_ALIAS_SQUAT` | no |
| 224 | `FULLSHIELD_EXPERIMENTAL_NPM_SELFNAME` | no |
| 225 | `FULLSHIELD_EXPERIMENTAL_NPM_WORKSPACE_NAME` | no |
| 226 | `FULLSHIELD_EXPERIMENTAL_NPM_POPULAR_LIST` | no |
| 227 | `FULLSHIELD_EXPERIMENTAL_NPM_DISTANCE2` | no |
| 228 | `FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_INSTANCE` | no |
| 229 | `FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_OPTIONAL` | no |
| 230 | `FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_PEER` | no |
| 231 | `FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_ALIAS` | no |
| 232 | `FULLSHIELD_EXPERIMENTAL_NPM_REACH_DYNAMIC` | no |
| 233 | `FULLSHIELD_EXPERIMENTAL_NPM_REACH_EXPORTS` | no |
| 234 | `FULLSHIELD_EXPERIMENTAL_NPM_REACH_CONDITIONS` | no |
| 235 | `FULLSHIELD_EXPERIMENTAL_NPM_REACH_BIN` | no |
| 236 | `FULLSHIELD_EXPERIMENTAL_NPM_REACH_WORKER` | no |
| 237 | `FULLSHIELD_EXPERIMENTAL_NPM_REACH_SUBPATH` | no |
| 238 | `FULLSHIELD_EXPERIMENTAL_NPM_REACH_TRY` | no |
| 239 | `FULLSHIELD_EXPERIMENTAL_NPM_REACH_REEXPORT` | no |
| 240 | `FULLSHIELD_EXPERIMENTAL_NPM_REACH_TYPEONLY` | no |
| 241 | `FULLSHIELD_EXPERIMENTAL_NPM_DUALPACKAGE` | no |
| 242 | `FULLSHIELD_EXPERIMENTAL_NPM_PHANTOM_DEEP` | no |
| 243 | `FULLSHIELD_EXPERIMENTAL_NPM_OSV_RANGE` | no |
| 244 | `FULLSHIELD_EXPERIMENTAL_NPM_OSV_WITHDRAWN` | no |
| 245 | `FULLSHIELD_EXPERIMENTAL_NPM_OSV_CVSS` | no |
| 246 | `FULLSHIELD_EXPERIMENTAL_NPM_OSV_ALIAS` | no |
| 247 | `FULLSHIELD_EXPERIMENTAL_NPM_OSV_PURL` | no |
| 248 | `FULLSHIELD_EXPERIMENTAL_NPM_FIX_NESTED` | no |
| 249 | `FULLSHIELD_EXPERIMENTAL_NPM_SBOM_PURL` | no |
| 250 | `FULLSHIELD_EXPERIMENTAL_NPM_AUDIT_DIFF` | no |

---

## 46. Breadth Phases 95–107 (target: 1.2.0, rev 2026-10-21)

### 46.0 Why these, and the order of work
Brainstormed ~30 candidates. Kept only gaps that (a) are real vulnerability classes in shipped Node/TS code that FullShield misses today, and (b) can be precise by construction. Rejected list is 46.3.

**Precondition (human, R1):** before any 46.x phase is promoted, Section 41 items 1–2 are done for at least NodeGoat and goof. New rules ship experimental (R11) until then. Every rule ID below is new → 1.2.0 is a **minor** (R16a).

AUTOPILOT runs may build 46.x phases but must not promote any rule out of experimental (R11) until the human precondition (Section 41 items 1–2 on NodeGoat and goof) is recorded as done.

Three tiers:
- **Tier P (pattern rules, near-zero FP by construction):** 95, 96, 102, 105. Candidates for fast promotion (see 46.2).
- **Tier T (taint rules, need precision sampling):** 97, 98, 99, 100, 101, 103, 104.
- **Tier H (heuristic, may never be stable):** 106, 107.

All Section 0, 37 header, 39.1, and 42.1 rules apply. Every rule: `rules/<ID>.md`, positive + negative fixture written from scratch (B8), failing test first (R4), compliance row (22.6), mutation target (Q10), flag-off byte-identical test, clean-app 0 with flag on.

---

### Phase 95 — Disabled TLS verification [`FULLSHIELD_EXPERIMENTAL_TLS`] (Tier P)
| ID | Detects | Sev | CWE |
|---|---|---|---|
| SAST-TLS-001 | `rejectUnauthorized: false` in options passed to `https.request/get`, `tls.connect`, `new https.Agent`, axios `httpsAgent`, undici `Agent({ connect })`, got `https.rejectUnauthorized`, `pg`/`mysql2`/`mongodb` `ssl`/`tls` options; `checkServerIdentity: () => undefined` | high | CWE-295 |
| SAST-TLS-002 | `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` in source; same var set to 0 in `Dockerfile ENV`, `package.json` scripts, compose `environment`, committed `.env*` | high | CWE-295 |

- Files under `test/`, `__tests__/`, `*.test.*`, `*.spec.*`, `scripts/dev*` → severity low, `context: "test"`.
- A value guarded by `process.env.NODE_ENV !== 'production'` in the same `if` → medium, not dropped.
- Negative fixtures: `rejectUnauthorized: true`, a variable whose value can't be resolved (not flagged), a `ca:` option set.

FP risk: dev-only scripts in non-test folders. Covered by the NODE_ENV-guard fixture and the scripts/dev* rule.

### Phase 96 — Crypto v2 [`FULLSHIELD_EXPERIMENTAL_CRYPTO2`] (Tier P)
| ID | Detects | Sev | CWE |
|---|---|---|---|
| SAST-CIPHER-001 | `createCipheriv('*-ecb', ...)`; deprecated `crypto.createCipher`/`createDecipher`; IV that is a string/Buffer literal or `Buffer.alloc(n)` (all zeros) | high | CWE-327/329 |
| SAST-CIPHER-002 | Symmetric key passed as a string literal to `createCipheriv`/`createHmac` | high | CWE-321 |
| SAST-RSA-001 | `generateKeyPair('rsa', { modulusLength < 2048 })`; `ec` with `secp192*` | medium | CWE-326 |
| SAST-JWT-002 | `jwt.sign` with no `expiresIn`/`exp`; or HMAC secret literal shorter than 32 bytes | medium | CWE-613/326 |

- `SAST-CIPHER-002` must not duplicate `SECRET-JWT-*` / generic-entropy findings on the same line (test asserts exactly one).
- Negative: `randomBytes(16)` IV, `aes-256-gcm`, key from `process.env`, `expiresIn: '1h'`.

FP risk: test vectors in crypto test files → test-context rule from 95.

### Phase 97 — Server-side template injection [`FULLSHIELD_EXPERIMENTAL_SSTI`] (Tier T)
| ID | Detects | Sev | CWE |
|---|---|---|---|
| SAST-SSTI-001 | Tainted value used as the **template source** (not data) in `ejs.render/compile`, `pug.render/compile`, `handlebars.compile`, `nunjucks.renderString`, `_.template`, `doT.template`, `Mustache.render` (arg 0), `new Function`-backed engines | critical | CWE-1336 |

- Argument role (template vs data) comes from Phase 81 model packs. No pack entry → no finding.
- Tainted data in the data argument is never SSTI (negative fixture). That remains XSS's job.
- RASP (experimental): add template-source hook to Phase 71 list only after static rule is merged.

### Phase 98 — Secrets written to logs [`FULLSHIELD_EXPERIMENTAL_LOGLEAK`] (Tier T)
| ID | Detects | Sev | CWE |
|---|---|---|---|
| SAST-LOGLEAK-001 | `console.*`, winston, pino, bunyan, debug, morgan custom tokens logging: `req.headers.authorization`, `req.headers.cookie`, whole `req.body` on routes matching auth names, or an identifier named `password|passwd|secret|token|apiKey|authorization` | medium | CWE-532 |

- pino/winston `redact` config covering the path clears it.
- Negative: logging `user.id`, logging `req.body` on a non-auth route (not flagged in this phase; noise).

FP risk: identifiers like `tokenCount`. Name match is whole-word on camelCase segments; `tokenCount` fixture is negative.

### Phase 99 — Unverified webhooks [`FULLSHIELD_EXPERIMENTAL_WEBHOOK`] (Tier T)
| ID | Detects | Sev | CWE |
|---|---|---|---|
| SAST-WEBHOOK-001 | Route whose handler reads a provider event shape (Stripe `event.type` from body, `x-github-event`, Slack `x-slack-signature` route, Shopify `x-shopify-hmac-sha256`, Twilio) and never calls that provider's verifier (`stripe.webhooks.constructEvent`, `@octokit/webhooks` verify, HMAC + `timingSafeEqual` on the signature header, Slack signing check) on any path in the handler | high | CWE-345 |

- Only providers with a model-pack entry. Unknown provider → no finding.
- Verifier in app-level middleware mounted on that path counts (reuse Phase 75 mount resolution).
- Negative: verifier present; `===` comparison of signature → reported as `SAST-TIMING-001` (existing), not here.

### Phase 100 — Session fixation [`FULLSHIELD_EXPERIMENTAL_SESSION2`] (Tier T)
| ID | Detects | Sev | CWE |
|---|---|---|---|
| SAST-SESSION-002 | Login handler (route name/auth heuristics) that writes `req.session.<user|userId|uid|auth*>` without `req.session.regenerate` earlier on the same path | medium | CWE-384 |

- passport `req.login`/`req.logIn` counts as regenerate **only** when locked passport version ≥ 0.6.0 (read from lockfile). Older passport → finding, message names the version.
- Negative: regenerate callback wraps the write; passport ≥ 0.6.

### Phase 101 — Browser-side JS [`FULLSHIELD_EXPERIMENTAL_BROWSER`] (Tier T, largest phase)
FullShield is server-only today. Many Node repos ship the frontend in the same repo.

| ID | Detects | Sev | CWE |
|---|---|---|---|
| SAST-DOMXSS-001 | Sources `location.hash/search/href`, `document.URL`, `document.referrer`, `window.name`, `URLSearchParams(location.*)`, message `event.data` → sinks `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, string `setTimeout/setInterval`, `el.src/href` assignment without scheme check, jQuery `$(tainted)`/`.html()` | high | CWE-79 |
| SAST-REACT-001 | `dangerouslySetInnerHTML={{ __html: x }}` where `x` is not a literal and not passed through DOMPurify/sanitize-html; Vue `v-html`; Svelte `{@html}` | medium | CWE-79 |
| SAST-POSTMSG-001 | `addEventListener('message', h)` where `h` uses `event.data` with no `event.origin` comparison; `postMessage(secretNamed, '*')` | medium | CWE-346 |
| SAST-TOKENSTORE-001 | Writing an identifier named token/jwt/accessToken to `localStorage` | low | CWE-922 |

- A file is "browser" only if: under a bundler entry graph (vite/webpack/next `app|pages|components`), or imports react/vue/svelte, or `package.json` `browser` field. Server taint rules never run browser sources (test).
- Next.js `'use client'` files are browser; `'use server'` are not.

FP risk: React `__html` from a trusted CMS sanitized server-side. Medium severity, fixture with server-side sanitize documents it stays reported (cannot see across the network boundary).

### Phase 102 — Electron hardening [`FULLSHIELD_EXPERIMENTAL_ELECTRON`] (Tier P)
Runs only when `electron` is in the dependency graph.

| ID | Detects | Sev |
|---|---|---|
| CONFIG-ELECTRON-001 | `webPreferences` with `nodeIntegration: true`, `contextIsolation: false`, `sandbox: false`, `webSecurity: false`, `allowRunningInsecureContent: true` | high |
| CONFIG-ELECTRON-002 | `shell.openExternal(x)` where `x` is not a literal and has no `https:` scheme check | high |
| CONFIG-ELECTRON-003 | `BrowserWindow` loading remote URL with no `setWindowOpenHandler` and no `will-navigate` guard | medium |

Each option is a separate fixture. No new hard dep.

### Phase 103 — Next.js server boundary [`FULLSHIELD_EXPERIMENTAL_NEXT`] (Tier T)
| ID | Detects | Sev |
|---|---|---|
| SAST-NEXT-001 | Exported `'use server'` function that writes to a DB/model-pack sink with no auth call (`auth()`, `getServerSession`, `currentUser`, `cookies()` + verify, or a user-configured name) in its body or called helper (depth 2) | medium, low confidence |
| CONFIG-NEXT-001 | Auth enforced only in `middleware.ts` (matcher covers route, handler has no auth call) → one info per app, message points to the 2025 middleware-bypass class and says enforce in the handler | info |
| CONFIG-NEXT-002 | `images.remotePatterns` with hostname `'**'` or `domains: ['*']` | medium |
| SECRET-NEXTPUB-001 | `NEXT_PUBLIC_*` env name containing `SECRET|PRIVATE|KEY` (except `PUBLISHABLE`) | high |

Next.js version vulns stay `DEPS-VULN-001` from OSV (R6). This phase never encodes a CVE range.

### Phase 104 — Vendored library versions [`FULLSHIELD_EXPERIMENTAL_VENDORED`] (Tier T)
deps reads lockfiles only. A `public/js/jquery-1.8.3.min.js` is invisible today.

| ID | Detects | Sev |
|---|---|---|
| DEPS-VENDORED-001 | JS file under `public/`, `static/`, `assets/`, `vendor/`, `lib/`, or any `*.min.js` whose header banner or exported `VERSION` constant identifies one of: jquery, jquery-ui, bootstrap, angular, lodash, underscore, moment, handlebars, dompurify, knockout. Mapped to `npm:<pkg>@<version>` and queried in OSV | per OSV |

- Banner regexes live in `models/vendored.json`, one per library, each with a fixture. No banner match → nothing. Never guess a version from file size or hash.
- `reachability: 'vendored'`. Shown in Phase 47 console (served to browsers = exposed). Fix: replace file; never edited automatically.
- `--offline` uses the OSV cache.

### Phase 105 — Committed credential files [`FULLSHIELD_EXPERIMENTAL_CREDFILES`] (Tier P)
| ID | File | Detected when |
|---|---|---|
| SECRET-FILE-002 | `.npmrc` | `_authToken=` or `_auth=` with a literal (not `${...}`) |
| SECRET-FILE-003 | `.docker/config.json`, `config.json` with `auths` | `auth` value present |
| SECRET-FILE-004 | kubeconfig (`apiVersion: v1` + `kind: Config`) | `token:` or `client-key-data:` |
| SECRET-FILE-005 | `*.tfstate`, `*.tfstate.backup` | any committed file (state holds secrets) |
| SECRET-FILE-006 | JSON with `"type": "service_account"` + `private_key` | present |
| SECRET-FILE-007 | `id_rsa`, `id_ed25519`, `*.p12`, `*.pfx`, `*.keystore` without `.pub` | present |

All critical except `.tfstate` (high). Masked. Same rotate remediation as 7.2. `--staged` covers them (pre-commit).

### Phase 106 — Unmaintained + unfixed dependencies [`FULLSHIELD_EXPERIMENTAL_HEALTH`] (Tier H)
| ID | Detects | Sev |
|---|---|---|
| DEPS-UNFIXED-001 | Production dependency with an OSV advisory that has **no fixed version**, and whose last registry publish is > 730 days ago | medium |

- registry.npmjs.org only (R15), shares Phase 87 cache. Unknown publish date → no finding.
- Remediation lists replacement as a human decision; never names a replacement package.
- Folded in console unless reachable.

### Phase 107 — Ownership-check hints [`FULLSHIELD_EXPERIMENTAL_IDOR`] (Tier H, may never promote)
| ID | Detects | Sev |
|---|---|---|
| SAST-IDOR-001 | Authenticated route with a `:id`-style param whose handler loads by that param (`findById`, `findByPk`, `findUnique({ where: { id } })`, `WHERE id =`) and never references `req.user`, `req.session.user*`, `ctx.state.user`, or a configured owner name anywhere in the handler or called helper (depth 2) | low, low confidence |

- `source: 'rule'`, `confidence: 'low'`, never affects `--fail-on` (test). Section 4.3 non-goal stands: this is a hint.
- Admin-guarded routes (middleware name contains `admin|role|permission|authorize`) → no finding.
- Promotion requires human-sampled precision ≥ 70% with n ≥ 30 (R1 decides). If not reached, it stays experimental permanently.

---

### 46.0a File rule for this section (R27)
- **R27.** Section 46 lives inside `SECURITY_SCANNER_SPEC.md`. Cursor never renames that file, never splits it, and never creates a second spec, plan, queue, or run-prompt file (R25 still applies). Status updates are edits to this file and to the day's report file only.
- Cursor never renames or moves an existing file in the repo (source, rule doc, fixture, script, doc) as part of a 46.x phase. A rename needs the human's "go" (R1).
- The only new files a 46.x phase may create are the ones its definition of done requires: `rules/<ID>.md`, its fixtures under `test/fixtures/`, its tests under `test/`, its model-pack entry under `models/`, and the day's `reports/<date>.md`. Anything else new → stop that phase and list it under "Needs human decision".
- Precedence: during an AUTOPILOT run (Section 45), R26 item 4 overrides R27 and Section 40.5. No report file is written for that run.

### 46.1 Work order (Cursor)
Order: 105 → 95 → 96 → 102 → 104 → 97 → 99 → 100 → 98 → 103 → 101 → 106 → 107.
Tier P first because each is small and testable in isolation. 101 last among Tier T because it is the largest and depends on the bundler-entry classifier.
Report file: `reports/<date>.md`, Section 40.5 rules. Definition of done: 42.1. One flag per phase, one merge at a time, default-scan-diff EMPTY.
Under AUTOPILOT, this order must be copied into the 1.2.0 version scope; the scope is the only queue autopilot reads.

### 46.2 Needs human decision before 1.2.0
1. **Promotion criterion for pattern rules.** Phase 43 requires an untouched-holdout recall gain for SAST. Tier P rules (95, 96, 102, 105) find config mistakes that holdout apps mostly don't contain, so they can never meet that bar. Proposal: Tier P rules qualify with (a) 0 human-confirmed FPs in a 20-finding sample across `bench/realworld.json`, and (b) clean-app 0. This is an R1 threshold change. Approve, reject, or amend.
2. Whether 1.2.0 ships with Tier P promoted (stable-output change, R10) or all 13 flagged.
3. Section 41 items 1–2 completed first (strongly recommended; without them no 1.2.0 number is citable).

### 46.3 Brainstormed and rejected
- Header/CRLF injection: Node rejects CR/LF in header values (`ERR_INVALID_CHAR`). Near-zero real yield.
- Log injection (CWE-117): low impact, high noise.
- Python/Go support: breaks "JS/TS only" positioning; Semgrep already wins there.
- More `--verify-secrets` providers: each one adds a network host (R15) for marginal value.
- Container/OS scanning, VS Code extension, PR comment bot: already rejected (Section 31).
- AI triage revival: Section 18.3 smoke results were not good enough; no new evidence.
- Auto-generated fix PRs to GitHub: violates 22.8 / Section 31.
- License-compliance expansion: not a security feature; dilutes positioning.
- Race-condition / TOCTOU detection: no precise static signal in JS.
- Prototype-pollution gadget chains through deps: research project, not a phase.
- Merging CyberShield (IoT network SDK) into FullShield: different buyer, different runtime, would violate Section 31 non-goals.

---

## 47. npm Depth Phases 108–250 (target: 1.2.0)

### 47.0 Why npm is thin

Default `scan` treats npm as a list of `name@version` rows. It asks OSV, classifies reachability from import strings, and flags a direct name that is one edit from a popular package. These facts are not on that scan:

- `npm-shrinkwrap.json` is not a lockfile name. `peerDependencies` are not direct roots. The edge map unions every nested copy of a name into one set (`src/modules/deps/lockfile.ts`).
- Resolved URL, integrity, cooldown, dependency confusion, and provenance drop exist as supply helpers. They run from `fullshield install`, not from `scan`.
- Registry `dist.integrity` is not compared with the lockfile. The tarball is not downloaded. Transitive lifecycle scripts are not listed.
- Typosquat detection is Levenshtein distance 1, direct dependencies only, no homoglyphs, no scope check.
- OSV range type, withdrawn advisories, and alias dedupe are not handled. A GIT range must not be read as semver.

Section 38 point 2 stays. This section does not claim parity with npm audit or OSV-Scanner. It adds the missing npm facts. Advisory text still comes only from OSV or a user-supplied `npm audit --json` file (R6).

**In the 1.2.0 queue.** Section 45 lists these phases after 107, in numeric order. One phase per commit (R19). No promotion (R11) until Section 41 items 1–2 are done for NodeGoat and goof. Lanes A–H are groups inside that one version.

**R28.** Phases 108–250 live in this file. Do not split them into a second spec.

### 47.1 Rules for every phase in this section

- Experimental. `FULLSHIELD_EXPERIMENTAL_<NAME>=1` or `scan --experimental-<name>`. Off leaves `scan --json` byte-identical on existing fixtures.
- One new rule ID unless the phase says it emits none. `rules/<ID>.md`, positive fixture, negative fixture, failing test first (R4), compliance row (22.6), mutation target (Q10). Fixtures are written from scratch (B8). Inert: `example.invalid`, no live payload.
- `clean-app` stays at 0 with the flag on (R12).
- No new hard dependency (R13). No new host (R15). Registry reads use `https://registry.npmjs.org` only. Advisory reads use OSV only. `--offline` uses the cache; a miss emits nothing and does not guess.
- Never run `npm install`, `npm audit`, or a lifecycle script. Never execute a tarball file. Never edit a lockfile. Override proposals write `package.json` only and print `run npm install`.
- Do not reimplement a shipped ID. If a supply helper already describes the same lock line, this phase uses its own ID. When both flags are on, emit the `DEPS-*` row and suppress the older `SUPPLY-*` row for that same package version (one test). `DEPS-MALICIOUS-001` is never suppressed or downgraded.
- Severity under a flag does not change default `scan`. A phase that would remove or relabel a stable finding stays flagged until an R10 approval.
- Definition of done is Section 42.1. Shared files are appended to.

### 47.2 One version

Phases 108–250 ship in `1.2.0` with phases 95–107. Section 45 is the order. Lanes below are reading groups, not later releases. New rule IDs stay experimental in this version (R11). Default `scan --json` does not change until a human promotes a flag (R10).

### 47.3 Rejected for this section

- Download counts (`api.npmjs.org/downloads/...`). That host is not in R15. Age comes from the packument `time` field.
- Socket, deps.dev, Snyk, npms.io, or the GitHub advisory API. OSV and `registry.npmjs.org` only.
- A sandbox that runs install scripts. R15 forbids executing analyzed packages.
- Levenshtein distance 2 as a finding. Phase 227 locks the negative test.
- Editing lockfiles, running the project's tests, or shelling out to `npm audit`.
- EPSS and KEV. Still Phase 56, still blocked on an R15 amendment.

---

### Lane A — Lockfile truth (108–127)

Read the lockfile the repo already has. No registry call in this lane.

### Phase 108 — npm-shrinkwrap.json [`FULLSHIELD_EXPERIMENTAL_NPM_SHRINKWRAP`]
`DEPS-SHRINKWRAP-001` (info) when `npm-shrinkwrap.json` is the only lockfile: parse it with the package-lock parser and query OSV as usual under this flag. `DEPS-SHRINKWRAP-002` (high) when both shrinkwrap and `package-lock.json` exist and their name@version sets differ. Negative: only `package-lock.json`, or both files with the same set. Flag off: shrinkwrap is ignored, as today.

### Phase 109 — lockfileVersion [`FULLSHIELD_EXPERIMENTAL_NPM_LOCKVER`]
`DEPS-LOCKVER-001` (medium) when `lockfileVersion` is missing, 1, or greater than 3. Version 1 still uses the dependencies-tree parser; do not drop packages. Negative: version 2 and version 3. Unknown version sets `edgesKnown: false` rather than inventing edges.

### Phase 110 — multiple lockfiles [`FULLSHIELD_EXPERIMENTAL_NPM_MULTLOCK`]
`DEPS-MULTLOCK-001` (medium) when two or more of `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` exist at the repo root. The message names the files. Negative: exactly one. Does not choose a winner. Scan continues to use today's single-file picker until Phase 108 is also on, in which case shrinkwrap joins the set.

### Phase 111 — root version drift [`FULLSHIELD_EXPERIMENTAL_NPM_ROOTVER`]
`DEPS-ROOTVER-001` (medium) when `packages[""].version` is a string and it differs from `package.json` `version`. Negative: equal versions, or no root entry. Do not flag a workspace package here (Phase 54).

### Phase 112 — non-semver locked version [`FULLSHIELD_EXPERIMENTAL_NPM_NONSEMVER`]
`DEPS-NONSEMVER-001` (medium) when a locked version is not `MAJOR.MINOR.PATCH` with optional prerelease (git sha, `file:`, `*`, empty). Negative: `1.2.3` and `1.2.3-beta.1`. OSV is not queried with a rewritten version.

### Phase 113 — missing resolved [`FULLSHIELD_EXPERIMENTAL_NPM_NORESOLVED`]
`DEPS-NORESOLVED-001` (medium) when a `packages` entry has a semver version and no `resolved`, excluding the root `""` entry and `link:` workspace rows. Negative: a `resolved` URL, and a `link:` row.

### Phase 114 — resolved host [`FULLSHIELD_EXPERIMENTAL_NPM_RESOLVED_HOST`]
`DEPS-RESOLVED-HOST-001` (high) when `resolved` is a URL whose host is not `registry.npmjs.org`. Negative: that host. Same fact as `SUPPLY-LOCKURL-001`; under both flags emit only this ID. `http:` URLs are Phase 115, not this one: if the protocol is `http:`, skip here.

### Phase 115 — cleartext tarball URL [`FULLSHIELD_EXPERIMENTAL_NPM_RESOLVED_HTTP`]
`DEPS-RESOLVED-HTTP-001` (high) when `resolved` uses `http:`. Negative: `https://registry.npmjs.org/...`. A `git+ssh:` URL is Phase 120, not this one.

### Phase 116 — missing integrity [`FULLSHIELD_EXPERIMENTAL_NPM_NOINTEGRITY`]
`DEPS-NOINTEGRITY-001` (high) when `resolved` is an https registry URL and `integrity` is missing or empty. Negative: `integrity` present. `link:` and `file:` rows are not this finding (they have no registry integrity). Dedupe against `SUPPLY-LOCKINTEGRITY-001` the same way as Phase 114.

### Phase 117 — weak integrity algorithm [`FULLSHIELD_EXPERIMENTAL_NPM_WEAKINTEGRITY`]
`DEPS-WEAKINTEGRITY-001` (medium) when `integrity` uses `sha1` or `sha256`. npm's registry algorithm is `sha512`. Negative: `sha512-` and a missing integrity (that is Phase 116 only).

### Phase 118 — integrity grammar [`FULLSHIELD_EXPERIMENTAL_NPM_BADINTEGRITY`]
`DEPS-BADINTEGRITY-001` (high) when `integrity` is non-empty and is not `algo-base64` with algo `sha1`, `sha256`, or `sha512`, or the base64 does not decode. Negative: a well-formed `sha512-` value. A weak but well-formed `sha1-` value is Phase 117 only.

### Phase 119 — link and file dependencies [`FULLSHIELD_EXPERIMENTAL_NPM_LINKDEP`]
`DEPS-LINKDEP-001` (medium) when `resolved` or the manifest spec is `file:` or `link:`. The message includes the path. Negative: a registry tarball. A path that escapes the repo root with `..` is high, same ID, and the fixture says so.

### Phase 120 — git dependencies [`FULLSHIELD_EXPERIMENTAL_NPM_GITDEP`]
`DEPS-GITDEP-001` (high) when the spec or `resolved` is `git:`, `git+https:`, `git+ssh:`, `git+http:`, `github:`, `gitlab:`, `bitbucket:`, or `gist:`. Negative: a registry tarball. Do not clone the git URL (R15).

### Phase 121 — npm alias [`FULLSHIELD_EXPERIMENTAL_NPM_ALIAS`]
`DEPS-NPMALIAS-001` (medium) when a lock key or manifest spec uses `npm:` and the requested name differs from the target name. The finding is attributed to the requested name and records the target `name@version`. Negative: `npm:same-name@1.2.3` where the name matches, and a normal entry. OSV is queried for the target, not the alias, and only under this flag.

### Phase 122 — bundled dependencies [`FULLSHIELD_EXPERIMENTAL_NPM_BUNDLED`]
`DEPS-BUNDLED-001` (medium) when a lock entry has `inBundle: true` or `bundled: true` and the root `bundleDependencies` / `bundledDependencies` array does not name that package. Negative: the root array names it. Bundled packages are still sent to OSV under this flag. Do not skip them.

### Phase 123 — undeclared peer [`FULLSHIELD_EXPERIMENTAL_NPM_PEER`]
`DEPS-PEER-UNDECLARED-001` (medium) when production code imports a package that the lock marks `peer: true` and the root `peerDependencies` does not name it. Negative: the peer is declared, or the import is only in a test file. `DEPS-PHANTOM-001` does not currently treat peers as declared; this phase does not change that rule. Flag off, phantom behavior stays.

### Phase 124 — imported optional dependency [`FULLSHIELD_EXPERIMENTAL_NPM_OPTIONAL`]
`DEPS-OPTIONAL-IMPORT-001` (low) when production code imports a package the lock marks `optional: true` and the import is not inside a `try/catch`. Negative: the import is inside `try/catch`, or the package is not optional. This does not downgrade a vulnerability on that package.

### Phase 125 — lockfile path shape [`FULLSHIELD_EXPERIMENTAL_NPM_LOCKPATH`]
`DEPS-LOCKPATH-001` (high) when a `packages` key is not `""` and does not start with `node_modules/`. Negative: `node_modules/foo` and `node_modules/foo/node_modules/bar`. A key containing `..` is the same ID.

### Phase 126 — manifest dependency omitted from the lock root [`FULLSHIELD_EXPERIMENTAL_NPM_LOCKOMIT`]
`DEPS-LOCKOMIT-001` (high) when `package.json` `dependencies` names a package that is absent from `packages[""].dependencies` and from the top-level `dependencies` object. Negative: the name is present. This is not `DEPS-LOCKMISMATCH-001` (that one compares a range to a locked version). A range that does not contain the locked version stays the old rule only.

### Phase 127 — dev edge into production [`FULLSHIELD_EXPERIMENTAL_NPM_DEVPROD`]
`DEPS-DEV-PROD-EDGE-001` (medium) when a package marked `dev: true` is also required by a package that is not `dev: true`. Negative: dev-only, and a production package with no dev parent. Dev-only vulnerabilities stay `dev-only` info. This finding is the edge, not a second advisory.

---

### Lane B — Manifest and project policy (128–147)

The project's own `package.json` and committed `.npmrc`. Home-directory `.npmrc` only with `scan --include-home`. Token literals in a committed `.npmrc` stay `SECRET-FILE-002` (Phase 105). Do not emit a second secret row.

### Phase 128 — floating specs [`FULLSHIELD_EXPERIMENTAL_NPM_FLOAT`]
`DEPS-FLOAT-001` (medium) when a direct spec is `*`, `x`, `X`, `latest`, or empty. `DEPS-FLOAT-002` (low) when a direct production spec is `>=` or `>` with no upper bound. Negative: `^1.2.3`, `~1.2.3`, and an exact `1.2.3`.

### Phase 129 — git spec in package.json [`FULLSHIELD_EXPERIMENTAL_NPM_GITSPEC`]
`DEPS-GITSPEC-001` (high) for a direct spec using the protocols in Phase 120. Negative: a semver range. If the lock `resolved` is also git, emit this ID and not `DEPS-GITDEP-001` when both flags are on.

### Phase 130 — file spec in package.json [`FULLSHIELD_EXPERIMENTAL_NPM_FILESPEC`]
`DEPS-FILESPEC-001` (medium) for a direct `file:` or `link:` spec. Negative: a semver range. Dedupe with `DEPS-LINKDEP-001` the same way.

### Phase 131 — URL spec in package.json [`FULLSHIELD_EXPERIMENTAL_NPM_URLSPEC`]
`DEPS-URLSPEC-001` (high) when a direct spec is an `http:` or `https:` URL whose host is not `registry.npmjs.org`. Negative: a semver range and a `https://registry.npmjs.org/` tarball URL.

### Phase 132 — dist-tag spec [`FULLSHIELD_EXPERIMENTAL_NPM_TAGSPEC`]
`DEPS-TAGSPEC-001` (medium) when a direct spec is a bare dist-tag (`next`, `beta`, `canary`, `latest` is Phase 128) or `name@tag` with no digit. Negative: `1.2.3-beta.1` and `^1.2.3`.

### Phase 133 — override pins a vulnerable version [`FULLSHIELD_EXPERIMENTAL_NPM_OVERRIDE_VULN`]
`DEPS-OVERRIDE-VULN-001` (high) when `overrides`, `resolutions`, or `pnpm.overrides` pins a single version and the OSV cache says that version is affected. The message cites the OSV id from the cache. No cache entry → no finding. Do not invent an advisory. Negative: the pinned version has an OSV cache file with `vulns: []`. `DEPS-VULN-001` may still exist for the locked copy; this row is about the override. Both may appear.

### Phase 134 — wide override [`FULLSHIELD_EXPERIMENTAL_NPM_OVERRIDE_WIDE`]
`DEPS-OVERRIDE-WIDE-001` (medium) when an override value is `*`, `latest`, `>=`, or `>`. Negative: an exact version and a `^` range. A `^` range is not this finding.

### Phase 135 — override npm alias [`FULLSHIELD_EXPERIMENTAL_NPM_OVERRIDE_ALIAS`]
`DEPS-OVERRIDE-ALIAS-001` (high) when an override value is `npm:other@version` and `other` differs from the key. Negative: an exact version. Phase 121 covers lock aliases; this one is the manifest override only.

### Phase 136 — lifecycle script in the root manifest [`FULLSHIELD_EXPERIMENTAL_NPM_LIFECYCLE`]
`CONFIG-LIFECYCLE-001` (high) when the root `scripts` `preinstall`, `install`, `postinstall`, or `prepare` contains `curl`, `wget`, `Invoke-WebRequest`, or a string that is an `http` URL piped to a shell. Negative: `"postinstall": "node scripts/build.js"` with no URL. This is the application manifest, not a dependency. Lockfile `hasInstallScript` info stays as it is.

### Phase 137 — project .npmrc registry [`FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_REG`]
`DEPS-NPMRC-REG-001` (high) when a committed `.npmrc` sets `registry=` to a URL whose host is not `registry.npmjs.org`. Negative: that host, and a file with only comments. Scoped registry lines (`@scope:registry=`) that point elsewhere are the same ID. This is not `SUPPLY-CONFUSION-001` (that one also needs a public package of the same name).

### Phase 138 — project .npmrc script settings [`FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_SCRIPT`]
`DEPS-NPMRC-SCRIPT-001` (info) when a committed `.npmrc` sets `ignore-scripts=false`. Negative: `ignore-scripts=true`, and no such key. Info only. It does not mean the project is compromised.

### Phase 139 — home .npmrc registry [`FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_HOME`]
`DEPS-NPMRC-HOME-001` (medium) when `scan --include-home` is set and `~/.npmrc` `registry` host is not `registry.npmjs.org`. Without `--include-home`, the home file is not read (test). Negative: the default host. Do not print token values. A token in `~/.npmrc` is out of scope for this phase (it is not a committed file).

### Phase 140 — packageManager field [`FULLSHIELD_EXPERIMENTAL_NPM_PACKAGEMANAGER`]
`DEPS-PACKAGEMANAGER-001` (low) when `packageManager` is missing and a lockfile exists. `DEPS-PACKAGEMANAGER-002` (medium) when the field is present and is not `<name>@<exact semver>` with name `npm`, `pnpm`, `yarn`, or `bun`. Negative: `npm@10.9.2`. The name must match the lockfile that is present (`package-lock.json` ↔ `npm`); a mismatch is `DEPS-PACKAGEMANAGER-002`.

### Phase 141 — Corepack integrity [`FULLSHIELD_EXPERIMENTAL_NPM_COREPACK`]
`DEPS-COREPACK-001` (info) when `packageManager` is `name@exact` and has no `+sha512.` hash suffix, and `package.json` has no `devEngines.packageManager` hash. Negative: a field that already contains `+sha512.`. Info only. Do not fetch the manager tarball.

### Phase 142 — engines vs pinned Node [`FULLSHIELD_EXPERIMENTAL_NPM_ENGINES`]
`CONFIG-ENGINES-001` (medium) when `.nvmrc` or `.node-version` exists and `engines.node` does not include that version. Use the existing semver helper. If the helper cannot parse the range, emit nothing. Negative: the range includes the pinned version, and a repo with no pin file.

### Phase 143 — engine-strict [`FULLSHIELD_EXPERIMENTAL_NPM_ENGINE_STRICT`]
`DEPS-ENGINE-STRICT-001` (info) when `engines.node` is set and a committed `.npmrc` sets `engine-strict=false`. Negative: `engine-strict=true`, and no engines field.

### Phase 144 — trustedDependencies [`FULLSHIELD_EXPERIMENTAL_NPM_TRUSTED`]
`DEPS-TRUSTED-001` (medium) when a committed `.npmrc` sets `ignore-scripts=true` and a direct production dependency's lock entry has `hasInstallScript: true` and the name is absent from root `trustedDependencies`. Negative: the name is listed, and `ignore-scripts` is not true. Missing `hasInstallScript` → no finding (do not guess from the packument; that is Phase 160).

### Phase 145 — publishConfig on a private package [`FULLSHIELD_EXPERIMENTAL_NPM_PUBLISHCONFIG`]
`DEPS-PUBLISHCONFIG-001` (high) when `private` is not `true` and `publishConfig.registry` host is not `registry.npmjs.org`. `DEPS-PUBLISHCONFIG-002` (medium) when `private` is `true` and `publishConfig.access` is `public`. Negative: private package with no publishConfig, and a public package whose publishConfig registry is the npm registry.

### Phase 146 — bin name collision [`FULLSHIELD_EXPERIMENTAL_NPM_BINSHADOW`]
`DEPS-BIN-SHADOW-001` (medium) when a direct dependency's lock or manifest `bin` name equals a Node builtin (`fs`, `path`, `child_process`, `http`, `https`, `net`, `tls`, `crypto`, `os`, `dns`) or equals a `bin` name of the root package. The dependency `bin` is read from `node_modules/<name>/package.json` when that file exists, otherwise from the packument cache filled by a later lane. No local file and no cache → no finding. Negative: a bin named `my-cli`.

### Phase 147 — os and cpu exclusion [`FULLSHIELD_EXPERIMENTAL_NPM_OSCPU`]
`DEPS-OSCPU-001` (info) when a direct production lock entry has `os` or `cpu` that excludes `process.platform` or `process.arch`. Negative: the array includes the current platform, and an empty field. Info only. Do not drop the package from OSV.

---

### Lane C — Registry packument (148–167)

Fetch `https://registry.npmjs.org/<name>` only. Cache under `~/.cache/fullshield/npm/` for 24h, same TTL idea as OSV. `--offline` reads that cache only. A miss, a non-200, or a packument without that version emits no finding. Never invent `time`, maintainers, or attestations. Do not follow `dist.tarball` in this lane (Lane D).

### Phase 148 — lock integrity vs registry [`FULLSHIELD_EXPERIMENTAL_NPM_REG_INTEGRITY`]
`DEPS-REG-INTEGRITY-001` (critical) when both the lock `integrity` and `versions[version].dist.integrity` are present and they differ. Negative: they match. Missing either side → no finding.

### Phase 149 — lock resolved vs registry tarball [`FULLSHIELD_EXPERIMENTAL_NPM_REG_TARBALL`]
`DEPS-REG-TARBALL-001` (high) when both URLs are present and the URL without query string differs. Negative: equal URLs. Host must already be `registry.npmjs.org` on both; a non-registry lock URL stays Phase 114.

### Phase 150 — registry deprecation [`FULLSHIELD_EXPERIMENTAL_NPM_REG_DEPRECATED`]
`DEPS-REG-DEPRECATED-001` (info) when the packument version has a non-empty `deprecated` string and the lock entry's `deprecated` is empty. Negative: the lock already carries the same string (`DEPS-DEPRECATED-001` only), and a version that is not deprecated.

### Phase 151 — unpublished version [`FULLSHIELD_EXPERIMENTAL_NPM_REG_UNPUBLISHED`]
`DEPS-REG-UNPUBLISHED-001` (critical) when the packument exists, `versions` is an object, and `versions[version]` is absent. Negative: the version is present. A failed fetch is not "unpublished".

### Phase 152 — publisher not a maintainer [`FULLSHIELD_EXPERIMENTAL_NPM_REG_NPMUSER`]
`DEPS-REG-NPMUSER-001` (medium) when `_npmUser.name` is a non-empty string and `maintainers` is a non-empty array and that name is not in it. Negative: the name is listed. Missing `_npmUser` → no finding.

### Phase 153 — maintainer set changed [`FULLSHIELD_EXPERIMENTAL_NPM_REG_MAINTAINER`]
`DEPS-REG-MAINTAINER-001` (medium) when a previous cache file for that package name exists and the sorted `maintainers[].name` set differs. The first cache fill emits nothing (test). Negative: the same set. This is not `SUPPLY-PROVENANCE-001`.

### Phase 154 — direct dependency has no attestation [`FULLSHIELD_EXPERIMENTAL_NPM_REG_PROV_ABSENT`]
`DEPS-REG-PROV-ABSENT-001` (info) when a direct production version's packument has no `dist.attestations` and no `dist.signatures`. Direct only. Negative: either field is non-empty. Does not replace `SUPPLY-PROV-001`. Info is not a malicious-package claim. Unknown because of a cache miss emits nothing.

### Phase 155 — attestation builder [`FULLSHIELD_EXPERIMENTAL_NPM_REG_BUILDER`]
`DEPS-REG-BUILDER-001` (medium) when `dist.attestations` is present and its builder identity is not in the checked-in allowlist `models/npm-builders.json`. The allowlist starts empty of guesses: it may contain only identities copied from npm's own docs in that file, each with a source URL. An identity not in the file is a finding. No attestation → no finding (Phase 154). Do not download a new allowlist.

### Phase 156 — attested source repo changed [`FULLSHIELD_EXPERIMENTAL_NPM_REG_REPO`]
`DEPS-REG-REPO-001` (medium) when the previous cache recorded an attested source repo and the current attestation names a different repo. First sight emits nothing. Negative: the same repo. Missing attestation → no finding.

### Phase 157 — attestation subject version [`FULLSHIELD_EXPERIMENTAL_NPM_REG_SUBJECT`]
`DEPS-REG-SUBJECT-001` (high) when an attestation subject version is present and it is not the locked version. Negative: the subject matches. A packument with no subject field → no finding.

### Phase 158 — packument time [`FULLSHIELD_EXPERIMENTAL_NPM_REG_TIME`]
`DEPS-REG-TIME-001` (medium) when `time[version]` is missing, does not parse, or is after the scan clock. Negative: a past timestamp. Do not flag a young package here (`SUPPLY-COOLDOWN-001` already does age).

### Phase 159 — young transitive release [`FULLSHIELD_EXPERIMENTAL_NPM_REG_TRANSITIVE_AGE`]
`DEPS-REG-AGE-001` (low) when a transitive production package's `time[version]` is younger than `deps.minReleaseAgeHours` (default 72). Direct packages stay on `SUPPLY-COOLDOWN-001` only, even if that helper did not run: this phase does not emit a second cooldown row for a direct dependency (test). Negative: older than the window, and a direct dependency. Missing `time` → no finding.

### Phase 160 — registry install-script flag [`FULLSHIELD_EXPERIMENTAL_NPM_REG_INSTALLSCRIPT`]
`DEPS-REG-INSTALLSCRIPT-001` (info) when packument `hasInstallScript` is `true` or that version's `scripts` has `preinstall`, `install`, or `postinstall`. One row per package version. Negative: no such scripts. The root lockfile `hasInstallScript` info remains one row; this phase names the package. Script bodies are Lane E, not this phase.

### Phase 161 — empty registry signatures [`FULLSHIELD_EXPERIMENTAL_NPM_REG_SIGNATURES`]
`DEPS-REG-SIGNATURES-001` (info) when `dist.signatures` is present and is an empty array. Negative: a non-empty array, and a version with no `signatures` key (old packages are not findings).

### Phase 162 — dependency engines vs project engines [`FULLSHIELD_EXPERIMENTAL_NPM_REG_ENGINES`]
`DEPS-REG-ENGINES-001` (medium) when both the project `engines.node` and the locked version's `engines.node` parse and they do not intersect. Negative: they intersect. Unparseable range → no finding.

### Phase 163 — locked version is not the newest in range [`FULLSHIELD_EXPERIMENTAL_NPM_REG_DRIFT`]
`DEPS-REG-DRIFT-001` (info) when the manifest range parses, the packument `versions` object has a greater version that satisfies the range, and the locked version is smaller. Versions come from the packument keys only. Negative: the locked version is the greatest satisfying key. This is drift, not an advisory, and it must not name a version that is absent from the packument.

### Phase 164 — packument dependency range vs lock [`FULLSHIELD_EXPERIMENTAL_NPM_REG_DEPS`]
`DEPS-REG-DEPS-001` (medium) when packument `versions[version].dependencies[name]` is a range the semver helper understands and the locked version of `name` does not satisfy it. Negative: it satisfies, and a range the helper cannot parse (no finding). Do not rewrite the lock.

### Phase 165 — unmet peer from the packument [`FULLSHIELD_EXPERIMENTAL_NPM_REG_PEER`]
`DEPS-REG-PEER-001` (medium) when packument `peerDependencies` names a package that is absent from the lock's package set, unless it is also in `peerDependenciesMeta` with `optional: true`. Negative: the peer is locked, and an optional peer that is absent.

### Phase 166 — bin path in the packument [`FULLSHIELD_EXPERIMENTAL_NPM_REG_BIN`]
`DEPS-REG-BIN-001` (high) when a packument `bin` target contains `..`, is absolute, or contains a backslash-dot-dot segment. Negative: `bin/cli.js`. Phase 146 is a name collision. This one is the path.

### Phase 167 — repository URL changed [`FULLSHIELD_EXPERIMENTAL_NPM_REG_REPOSITORY`]
`DEPS-REG-REPOSITORY-001` (info) when a previous cache had `repository.url` and the current packument has a different host, or the field disappeared. First sight emits nothing. Negative: the same host. Do not fetch the repository.

---

### Lane D — Tarball bytes (168–187)

Download `dist.tarball` only when its host is `registry.npmjs.org` and the lock integrity matches Phase 148 (or Phase 148's flag is off and the URL host is still that registry). Hash the bytes before opening them. A hash mismatch is Phase 168 and the tarball is not extracted. Cache by integrity under `~/.cache/fullshield/npm/tarballs/`. Cap: one tarball ≤ 20 MB, and this lane fetches direct production dependencies only. A transitive tarball is not downloaded (Phase 187 tests that). `--offline` uses the cache only. Never execute a file from the tarball. Extraction refuses absolute paths and `..` before any other check; that refusal is also the Phase 179 fixture.

### Phase 168 — tarball hash [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_HASH`]
`DEPS-TARBALL-HASH-001` (critical) when the downloaded bytes do not match `dist.integrity`. Negative: a fixture tarball whose sha512 matches. Network is mocked. Mismatch stops extraction for that package.

### Phase 169 — tarball identity [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_ID`]
`DEPS-TARBALL-ID-001` (critical) when the tarball's `package/package.json` `name` or `version` differs from the locked name and version. Negative: both match.

### Phase 170 — lifecycle script the packument hid [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_LIFECYCLE`]
`DEPS-TARBALL-LIFECYCLE-001` (high) when the tarball `scripts` has `preinstall`, `install`, or `postinstall` and the cached packument `hasInstallScript` is `false`. Negative: the packument flag is `true` (Phase 160 already listed it), and a package with no such scripts.

### Phase 171 — lifecycle script network [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_NET`]
`DEPS-TARBALL-NET-001` (high) when a lifecycle script string contains `http://`, `https://`, `fetch(`, or `dns`. Negative: a script that only runs `node scripts/build.js`. Fixture URLs use `example.invalid`.

### Phase 172 — lifecycle script shell [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_SHELL`]
`DEPS-TARBALL-SHELL-001` (high) when a lifecycle script string contains `curl`, `wget`, `bash`, `sh -c`, `powershell`, or `child_process`. Negative: `node scripts/build.js`.

### Phase 173 — lifecycle script credential read [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_CRED`]
`DEPS-TARBALL-CRED-001` (critical) when a lifecycle script string contains `.npmrc`, `.ssh`, `.aws`, `.git-credentials`, `NPM_TOKEN`, `NODE_AUTH_TOKEN`, or `npm_config__auth`. Negative: the same strings only inside a file under the tarball's `test/` directory, which is not a lifecycle script. Do not require a second signal. An install script that reads a credential file is the finding.

### Phase 174 — lifecycle script decode-and-eval [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_OBFUSC`]
`DEPS-TARBALL-OBFUSC-001` (high) when a lifecycle script passes a base64 literal of 32 or more characters to `eval`, `Function`, or `spawn`. Negative: a base64 literal shorter than 32 characters, and a long base64 literal that is only assigned to a string. Distinct from `SUPPLY-OBFUSCATE-001`, which scans installed trees: when both flags are on, emit this ID only for tarball lifecycle scripts.

### Phase 175 — bin target missing [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_BIN`]
`DEPS-TARBALL-BIN-001` (medium) when `package.json` `bin` points at a path that is not a file in the tarball. Negative: the file exists. A path with `..` is Phase 179 as well; emit 179 only for the escape, and 175 only when the path is inside the package and missing.

### Phase 176 — prebuilt native binary [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_NATIVE`]
`DEPS-TARBALL-NATIVE-001` (medium) when the tarball contains a `.node` file. Negative: a `binding.gyp` with no `.node` file. Medium is not a malware claim. The message says a prebuilt binary could not be reviewed as source.

### Phase 177 — git hook or workflow inside a dependency [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_HOOK`]
`DEPS-TARBALL-HOOK-001` (critical) when a tarball path includes `.git/hooks/` or `.github/workflows/`. Negative: a `README.md` that mentions those words. Distinct from `SUPPLY-WORKFLOW-001`, which looks at package source that writes those paths: dedupe to this ID when the path is an archived file.

### Phase 178 — hidden or bidi path [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_HIDDEN`]
`DEPS-TARBALL-HIDDEN-001` (medium) when a path segment contains a bidi override character, or a segment other than `.npmignore`, `.gitignore`, or `.github` starts with `.` and also contains a letter from a non-latin script. Negative: `.gitignore` and a normal `lib/index.js`.

### Phase 179 — tarball path escape [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_PATH`]
`DEPS-TARBALL-PATH-001` (critical) when an entry name is absolute or contains `..` after normalizing separators. The extractor skips that entry. Negative: `package/lib/index.js`. This check runs even when later phases are off, as soon as this flag is on.

### Phase 180 — tarball size [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_SIZE`]
`DEPS-TARBALL-SIZE-001` (info) when the unpacked size would exceed 20 MB or the entry count would exceed 2000. The tarball is not fully extracted past the cap. Negative: a small fixture. The cap is a limit, not a vulnerability count.

### Phase 181 — license field mismatch [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_LICENSE`]
`DEPS-TARBALL-LICENSE-001` (info) when both the tarball `license` and the packument `license` are strings and they differ. Negative: they match, and either side missing. This is not `DEPS-LICENSE-001` and it does not judge the license.

### Phase 182 — manifest swap [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_MANIFEST`]
`DEPS-TARBALL-MANIFEST-001` (high) when the tarball `dependencies` object differs from the packument version's `dependencies` object (key set or any range string). Negative: they match. Name and version mismatches stay Phase 169.

### Phase 183 — loose install.js [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_INSTALLJS`]
`DEPS-TARBALL-INSTALLJS-001` (medium) when the tarball contains `package/install.js`, `package/preinstall.js`, or `package/postinstall.js` and `scripts` has no matching key. Negative: the script key exists, and no such file.

### Phase 184 — top-level network or process in the entry [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_TOPLEVEL`]
`DEPS-TARBALL-TOPLEVEL-001` (high) when `main` or an `exports` target that is a file contains a `fetch(`, `http.request`, `https.request`, or `child_process` call that is not inside a function. Negative: the same call inside a function declaration. Parse with the existing parser. A file that does not parse emits nothing for this rule.

### Phase 185 — entry exfiltrates the environment [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_ENV`]
`DEPS-TARBALL-ENV-001` (critical) when a `main` or `exports` file passes `process.env` (the whole object) to `fetch`, `http.request`, or `https.request`. Negative: `process.env.NODE_ENV` only. Fixture hosts are `example.invalid`.

### Phase 186 — top-level dynamic import [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_DYNAMIC`]
`DEPS-TARBALL-DYNAMIC-001` (medium) when `main` or an exports file contains `require(` or `import(` whose argument is not a string literal, and the call is not inside a function. Negative: the call is inside a function, and a literal `require('fs')`.

### Phase 187 — direct-only fetch gate [`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_GATE`]
`DEPS-TARBALL-SKIP-001` (info) when a direct production dependency has no `integrity`, so its tarball is refused. One row. A test counts HTTP calls and asserts a transitive package produced zero. Negative: every direct production dependency has integrity and no skip row is emitted. This phase does not download transitive tarballs.

---

### Lane E — Lifecycle scripts (188–207)

Use the lock `hasInstallScript` bit and, when a Lane D cache entry exists, the script text. Do not run scripts. Do not download a tarball from this lane. No cache and no `hasInstallScript` bit → no finding, except phases that say they read only the lock bit.

### Phase 188 — transitive install script [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_TRANSITIVE`]
`DEPS-SCRIPT-TRANSITIVE-001` (medium) one row per transitive production package whose lock entry has `hasInstallScript: true`. Negative: the bit is false, and a direct dependency (Phase 160 or the existing lock info covers direct; this ID is transitive only).

### Phase 189 — optional install script [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_OPTIONAL`]
`DEPS-SCRIPT-OPTIONAL-001` (medium) when an `optional: true` package has `hasInstallScript: true`. Negative: optional without the bit. If Phase 188 would also match, emit only this ID.

### Phase 190 — dev install script [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_DEV`]
`DEPS-SCRIPT-DEV-001` (info) when a `dev: true` package has `hasInstallScript: true` and Phase 127 did not mark it as also production. Negative: a production install script.

### Phase 191 — prepare script [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_PREPARE`]
`DEPS-SCRIPT-PREPARE-001` (high if the package is a git dependency from Phase 120, otherwise medium) when `scripts.prepare` is a non-empty string. Negative: no prepare script. `prepare` runs on local `npm install` for git dependencies; the message says that.

### Phase 192 — prepublish script [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_PREPUBLISH`]
`DEPS-SCRIPT-PREPUBLISH-001` (high) when `scripts.prepublish` is set. `prepublishOnly` is medium, same ID, and the message names which key. Negative: only `prepublishOnly` is not high; the fixture expects medium. No such keys → no finding. Old npm runs `prepublish` on install. The message says that.

### Phase 193 — pipe to a shell [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_CURL`]
`DEPS-SCRIPT-CURL-001` (critical) when a lifecycle script matches `curl` or `wget` and a pipe to `sh`, `bash`, or `node`. Negative: `curl` written to a file with no pipe, and a script with neither command. Fixture URL host is `example.invalid`.

### Phase 194 — base64 to eval in a script [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_BASE64`]
`DEPS-SCRIPT-BASE64-001` (high) same condition as Phase 174, applied to lock-known script text when the tarball was not fetched. If Phase 174 already fired for that package, emit nothing here (test).

### Phase 195 — node-gyp URL [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_NODEGYP`]
`DEPS-SCRIPT-NODEGYP-001` (medium) when `binding.gyp` contains a URL whose host is not `registry.npmjs.org`. Negative: no URL, and a `registry.npmjs.org` URL. Read the file only from a cached tarball or from `node_modules/<name>/binding.gyp` if present. Do not compile.

### Phase 196 — script writes outside the package [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_WRITE`]
`DEPS-SCRIPT-WRITE-001` (high) when a lifecycle script contains a write path that starts with `..`, `/`, `~/`, or an env var expansion of `HOME` or `USERPROFILE`. Negative: a relative path `lib/out.js` with no `..`.

### Phase 197 — script mentions writing the lockfile [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_LOCK`]
`DEPS-SCRIPT-LOCK-001` (high) when a lifecycle script contains `package-lock.json` or `npm-shrinkwrap.json` next to `write`, `>`, or `fs.write`. Negative: a comment in a non-script file, and a script that does not name the lockfile.

### Phase 198 — script touches git [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_GIT`]
`DEPS-SCRIPT-GIT-001` (high) when a lifecycle script contains `git ` or `.git/hooks`. Negative: the word `digital` and a script that does not call git.

### Phase 199 — script reads an npm token [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_TOKEN`]
`DEPS-SCRIPT-TOKEN-001` (critical) when a lifecycle script contains `NPM_TOKEN`, `NODE_AUTH_TOKEN`, or `npm_config__auth`. If Phase 173 already fired for that package, emit nothing here.

### Phase 200 — script publishes [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_PUBLISH`]
`DEPS-SCRIPT-PUBLISH-001` (high) when a lifecycle script contains `npm publish` or `npm whoami`. Negative: neither string. `SUPPLY-WORM-001` stays the combination of token read plus publish. This ID is the publish string alone. When both would match, emit `SUPPLY-WORM-001` only if its flag is on and its combination is present; otherwise emit this ID. Do not emit both (test).

### Phase 201 — trusted dependency still has a dangerous script [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_TRUSTED`]
`DEPS-SCRIPT-TRUSTED-001` (medium) when the name is in root `trustedDependencies` and its script text matches Phase 193, 196, 197, 198, 199, or 200. The trust list does not clear those IDs. This row is additional and says the package was trusted. Negative: a trusted package whose script is `node scripts/build.js`.

### Phase 202 — hasInstallScript disagrees with scripts [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_MISMATCH`]
`DEPS-SCRIPT-MISMATCH-001` (medium) when the lock or packument says `hasInstallScript: true` and the tarball `scripts` object has none of `preinstall`, `install`, `postinstall`. Negative: the key exists. No tarball cache → no finding.

### Phase 203 — several lifecycle scripts [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_MULTI`]
`DEPS-SCRIPT-MULTI-001` (info) when a package has two or more of `preinstall`, `install`, `postinstall`. Negative: exactly one.

### Phase 204 — bin file is the install script [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_BIN`]
`DEPS-SCRIPT-BIN-001` (medium) when a `bin` target path equals the path named by `scripts.install` or `scripts.preinstall` after stripping `node `. Negative: different paths.

### Phase 205 — install script shebang [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_SHEBANG`]
`DEPS-SCRIPT-SHEBANG-001` (medium) when the install script file's first line is a shebang and the interpreter is not `node`, `sh`, or `bash`. Negative: `#!/usr/bin/env node`. No shebang → no finding. Read only from a cached tarball or `node_modules`.

### Phase 206 — environment-gated script [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_COND`]
`DEPS-SCRIPT-COND-001` (medium) when a lifecycle script branches on `process.env.CI` or `NODE_ENV` and the non-CI or production branch contains a Phase 193–200 pattern. Negative: the branch only changes a log string. If the pattern is unconditional, the earlier phase fires and this one does not.

### Phase 207 — install-script rollup [`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_ROLLUP`]
`DEPS-SCRIPT-ROLLUP-001` (info) one row for the repo when more than 25 production packages have `hasInstallScript: true`. The count is printed. Negative: 25 or fewer. Per-package rows stay on Phase 188. The threshold is 25 and is not a vulnerability count.

---

### Lane F — Package names (208–227)

`DEPS-TYPOSQUAT-001` stays distance 1, direct dependencies, length ≥ 4. Phases here add other IDs. They do not change that rule's fixtures. The popular list for new IDs is Phase 226's file once that phase has landed; until then a phase reads the existing `POPULAR_PACKAGES` list and must not widen it inside the same commit.

### Phase 208 — scope edit [`FULLSHIELD_EXPERIMENTAL_NPM_SCOPE_TYPO`]
`DEPS-SCOPE-TYPO-001` (medium) when a direct dependency `@scope/name` has a scope at Levenshtein distance 1 from a scope on the popular list, and `name` equals a popular package's basename in the real scope. Negative: the real scope, and a distance-1 scope whose basename is not on the list. Unscoped names are not this rule.

### Phase 209 — homoglyph [`FULLSHIELD_EXPERIMENTAL_NPM_HOMOGLYPH`]
`DEPS-HOMOGLYPH-001` (high) when a dependency name is not ASCII and its NFKC form equals a popular package name, or it contains a character from the Unicode confusable set for `a`, `e`, `o`, `p`, `c`, `x`, `y` (Cyrillic and Greek lookalikes only; the set is a literal in source, not fetched). Negative: an ASCII name, and a non-ASCII name that does not map to a popular package.

### Phase 210 — bidi in a name [`FULLSHIELD_EXPERIMENTAL_NPM_BIDI`]
`DEPS-BIDI-001` (critical) when a dependency name contains `U+202A`–`U+202E`, `U+2066`–`U+2069`, or `U+200B`–`U+200F`. Negative: an ASCII name.

### Phase 211 — mixed script [`FULLSHIELD_EXPERIMENTAL_NPM_MIXEDSCRIPT`]
`DEPS-MIXEDSCRIPT-001` (high) when a name contains both a Latin letter and a Cyrillic or Greek letter. Negative: Latin only, and Cyrillic only that did not match Phase 209. If Phase 209 matches, emit 209 only.

### Phase 212 — separator twin [`FULLSHIELD_EXPERIMENTAL_NPM_SEPARATOR`]
`DEPS-SEPARATOR-001` (medium) when a direct name equals a popular name after treating `.`, `-`, and `_` as the same character, and the names are not equal. Negative: the exact popular name, and a name that differs by a letter. If Levenshtein distance is also 1, emit `DEPS-TYPOSQUAT-001` only.

### Phase 213 — repeated token [`FULLSHIELD_EXPERIMENTAL_NPM_REPEAT`]
`DEPS-REPEAT-001` (medium) when a direct name is `foo-foo` or `@foo/foo` and `foo` is a popular package basename. Negative: `foo` itself, and a distance-1 name (that stays the old rule only).

### Phase 214 — suffix squat [`FULLSHIELD_EXPERIMENTAL_NPM_SUFFIX`]
`DEPS-SUFFIX-001` (low) when a direct name is a popular name plus `-js`, `-node`, `-npm`, or `-lib` and is not itself on the popular list. Low confidence. Negative: the popular name, and a suffix that is not in that list. May stay experimental. The message says to confirm intent. It does not say the package is malicious.

### Phase 215 — new scope [`FULLSHIELD_EXPERIMENTAL_NPM_SCOPE_NEW`]
`DEPS-SCOPE-NEW-001` (medium) when a direct scoped dependency's packument `time` for its earliest version is younger than 7 days and the scope is not the root package's scope. Missing packument → no finding. Negative: an older first publish, and the project's own scope. Age uses packument `time` only.

### Phase 216 — scope syntax [`FULLSHIELD_EXPERIMENTAL_NPM_SCOPE_SYNTAX`]
`DEPS-SCOPE-SYNTAX-001` (high) when a dependency name starts with `@` and does not match `@[a-z0-9-~][a-z0-9-._~]*/[a-z0-9-~][a-z0-9-._~]*`. Negative: `@scope/name`. This catches a missing slash and a second slash.

### Phase 217 — redundant @types [`FULLSHIELD_EXPERIMENTAL_NPM_TYPES`]
`DEPS-TYPES-001` (info) when the project depends on both `foo` and `@types/foo` and `foo`'s packument has a non-empty `types` or `typings` field. Negative: `foo` has neither field. No packument → no finding.

### Phase 218 — deprecation names a replacement [`FULLSHIELD_EXPERIMENTAL_NPM_DEPRECATED_REPLACE`]
`DEPS-DEPRECATED-REPLACE-001` (info) when a `deprecated` string contains `use <name>` or `replaced by <name>` and `<name>` matches the package-name grammar, and the root manifest does not depend on `<name>`. The name is taken from that sentence only. If the sentence does not contain a name, do not invent one (no finding beyond the existing deprecation row). Negative: the replacement is already a direct dependency.

### Phase 219 — transitive name checks [`FULLSHIELD_EXPERIMENTAL_NPM_TYPO_TRANSITIVE`]
Apply Phases 208–212 to transitive names as `DEPS-TYPO-TRANSITIVE-001` (info). One row per package, message names which check. Direct names do not use this ID. Negative: a direct typosquat still uses only `DEPS-TYPOSQUAT-001` or the direct-phase ID. `DEPS-MALICIOUS-001` is unchanged.

### Phase 220 — name length [`FULLSHIELD_EXPERIMENTAL_NPM_NAME_LENGTH`]
`DEPS-NAME-LENGTH-001` (high) when a dependency name is empty or longer than 214 characters. Negative: a normal name. npm's documented limit is 214.

### Phase 221 — case collision [`FULLSHIELD_EXPERIMENTAL_NPM_NAME_CASE`]
`DEPS-NAME-CASE-001` (high) when two locked names differ only by ASCII case. Negative: distinct names. One row naming both.

### Phase 222 — percent-encoding in a name [`FULLSHIELD_EXPERIMENTAL_NPM_NAME_ENCODED`]
`DEPS-NAME-ENCODED-001` (high) when a dependency name contains `%`. Negative: a name without `%`.

### Phase 223 — alias looks like a popular package [`FULLSHIELD_EXPERIMENTAL_NPM_ALIAS_SQUAT`]
`DEPS-ALIAS-SQUAT-001` (high) when an `npm:` alias's requested name is on the popular list and the target name is not. Negative: the target is the same popular package. Phase 121 still fires for a differing alias; this ID is additional only when the requested name is popular. Test asserts both IDs when both flags are on, because the facts differ (alias exists vs alias impersonates a popular name).

### Phase 224 — dependency name is the project name [`FULLSHIELD_EXPERIMENTAL_NPM_SELFNAME`]
`DEPS-SELFNAME-001` (medium) when a dependency name equals the root `package.json` `name` and it is not a workspace path (`file:` or `workspace:`). Negative: a workspace spec of the same name, and a different name.

### Phase 225 — workspace name resolved from the registry [`FULLSHIELD_EXPERIMENTAL_NPM_WORKSPACE_NAME`]
`DEPS-WORKSPACE-NAME-001` (high) when a workspace package name also appears as a registry `resolved` URL (host `registry.npmjs.org`) rather than `link:` or `file:`. Negative: `link:` to the workspace path. Requires the workspace flag's parser only as a reader; do not change Phase 54 output. Flag off, Phase 54 behavior stays.

### Phase 226 — popular-name list file [`FULLSHIELD_EXPERIMENTAL_NPM_POPULAR_LIST`]
No new finding ID. Move the names already in `POPULAR_PACKAGES` into `models/npm-popular.json` without adding names in this phase. Each entry is `{ "name": "<ascii package name>" }`. A test fails if a name is duplicated, contains uppercase, or is not valid package-name grammar. `DEPS-TYPOSQUAT-001` fixtures stay green. Adding a name is a later human edit to that file, not part of this phase.

### Phase 227 — distance 2 stays silent [`FULLSHIELD_EXPERIMENTAL_NPM_DISTANCE2`]
No new finding ID. A fixture name at Levenshtein distance 2 from a popular package produces no `DEPS-*` name finding under this flag and under `DEPS-TYPOSQUAT-001`. The test is the acceptance. This locks the 47.3 rejection in code.

---

### Lane G — Graph and reachability (228–242)

Flag off, reachability classes and `DEPS-PHANTOM-001` stay as they are today. Flag on, new classes may appear in JSON. They must not change `(ruleId, file, line, severity)` for `DEPS-VULN-001` until an R10 promotion. A new class is carried on `reachability` only when the flag is on. `DEPS-MALICIOUS-001` is never downgraded.

### Phase 228 — per-path edges [`FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_INSTANCE`]
Keep edges by lockfile path (`node_modules/a/node_modules/b`), not by a union of names. A vulnerable nested copy stays `reachable-via-dependency` when that path is required, even if another copy of the same name is unused. Negative: one copy, behavior matches today. Acceptance fixture: two copies, only the nested one is vulnerable, and the unused top copy is not used to mark the nested one `not-imported`.

### Phase 229 — broken optional edge [`FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_OPTIONAL`]
A missing optional dependency does not make its parent `not-imported`. `DEPS-GRAPH-OPTIONAL-001` (info) names the missing optional package. Negative: the optional package is present. Parent reachability is unchanged.

### Phase 230 — peer edge [`FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_PEER`]
`DEPS-PEER-MISSING-001` (medium) when a non-optional peer is absent from the lock. When the root provides it, the dependency path may go through the root. Negative: the peer is present. Does not change Phase 123's ID; a package can be missing (this phase) or imported without a root declaration (Phase 123). Tests use different fixtures.

### Phase 231 — alias edges [`FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_ALIAS`]
Imports of the alias name resolve to the target package's findings. `DEPS-GRAPH-ALIAS-001` (info) records alias → target. Negative: a non-alias import. OSV findings stay on the target version.

### Phase 232 — dynamic import and createRequire [`FULLSHIELD_EXPERIMENTAL_NPM_REACH_DYNAMIC`]
A literal `import('name')`, `require.resolve('name')`, or `createRequire(...)('name')` counts as an import. A non-literal argument does not count as `not-imported`; that specifier is `reachability-unknown`. Negative: a literal import already counted by the current walker, which must not produce a second finding.

### Phase 233 — exports map [`FULLSHIELD_EXPERIMENTAL_NPM_REACH_EXPORTS`]
Read `exports` from `node_modules/<name>/package.json` or the packument cache. A deep import blocked by `exports` is not a reach. A deep import allowed by `exports` is a reach. No `exports` field → today's behavior. Negative: a package with no `exports`. Do not mark `not-imported` solely because `exports` exists.

### Phase 234 — export conditions [`FULLSHIELD_EXPERIMENTAL_NPM_REACH_CONDITIONS`]
Honor `import`, `require`, `default`, and `node`. An export that exists only under `browser` is not a Node reach. Negative: a `default` export that still reaches the file. `react-native` and `electron` conditions are ignored unless that runtime is already a dependency (Electron reuses the Phase 102 detector only to decide the condition; it does not copy Electron rules).

### Phase 235 — script bin reachability [`FULLSHIELD_EXPERIMENTAL_NPM_REACH_BIN`]
A package named in a root `scripts` value as a bare command, whose `bin` matches that command, gets reachability `reachable-via-script` under this flag. It is not `not-imported`. The class is new and flag-only. Negative: a script that does not name the package. Severity of an existing advisory is unchanged.

### Phase 236 — worker and fork [`FULLSHIELD_EXPERIMENTAL_NPM_REACH_WORKER`]
`new Worker('name/...')` and `child_process.fork('name/...')` with a literal specifier count as a call, not only an import. Negative: a string that is not a call. Non-literal specifiers follow Phase 232.

### Phase 237 — subpath imports [`FULLSHIELD_EXPERIMENTAL_NPM_REACH_SUBPATH`]
`import 'pkg/subpath'` uses that `exports` target for symbol reachability when the advisory names a file. No symbol data → import-level only, as today. Negative: a subpath the package does not export, which is not a reach under Phase 233 when that flag is also on.

### Phase 238 — require in try/catch [`FULLSHIELD_EXPERIMENTAL_NPM_REACH_TRY`]
A `require` inside `try/catch` still counts as imported. Add `optionalImport: true` on the evidence object when Phase 61's flag is also on. Do not downgrade severity. Negative: a require outside `try/catch` has `optionalImport` absent. `DEPS-OPTIONAL-IMPORT-001` remains the separate finding from Phase 124.

### Phase 239 — re-exports [`FULLSHIELD_EXPERIMENTAL_NPM_REACH_REEXPORT`]
`export * from 'pkg'` and `export { x } from 'pkg'` count as imports of `pkg`. Depth stays 5. Negative: a type-only export, which is Phase 240 when that flag is on; with only this flag, `export type` is not an import (same negative).

### Phase 240 — type-only import [`FULLSHIELD_EXPERIMENTAL_NPM_REACH_TYPEONLY`]
`import type` and `export type { } from` are not runtime imports. A value import of the same module still counts. Negative: `import { x } from 'pkg'` remains a reach. This removes a false runtime reach under the flag only.

### Phase 241 — ESM-only package required from CJS [`FULLSHIELD_EXPERIMENTAL_NPM_DUALPACKAGE`]
`DEPS-DUALPACKAGE-001` (medium) when a CJS `require('pkg')` targets a package whose packument `type` is `module` and whose `exports` has no `require` condition. Negative: a `require` condition exists, and an ESM `import`. No packument → no finding.

### Phase 242 — phantom literals in dynamic import [`FULLSHIELD_EXPERIMENTAL_NPM_PHANTOM_DEEP`]
Under this flag only, also report `DEPS-PHANTOM-002` for a literal `import()`, `require.resolve`, or `createRequire` package name that is not in dependencies, devDependencies, optionalDependencies, or peerDependencies. Do not change `DEPS-PHANTOM-001`. Negative: the name is declared, and a non-literal import (no finding).

---

### Lane H — Advisory fidelity, fix, SBOM, audit diff (243–250)

OSV remains the only advisory source. These phases change how a cached OSV document is read. They do not add advisories the cache does not contain.

### Phase 243 — OSV range type [`FULLSHIELD_EXPERIMENTAL_NPM_OSV_RANGE`]
Honor `affected[].ranges[].type`. `SEMVER` uses the semver helper. `ECOSYSTEM` and `GIT` do not. A `GIT` range produces no `minFixedVersion` and no bump suggestion. Negative: a `SEMVER` range still suggests the fixed version already in the cache. A test feeds a `GIT` range and asserts no invented semver.

### Phase 244 — withdrawn advisory [`FULLSHIELD_EXPERIMENTAL_NPM_OSV_WITHDRAWN`]
Do not emit `DEPS-VULN-001` for an OSV object with a non-empty `withdrawn` timestamp, under this flag. Negative: no `withdrawn` field, the advisory still emits. Flag off, current behavior stays, including a withdrawn fixture if one is added only under the flag's test.

### Phase 245 — CVSS when OSV has no severity word [`FULLSHIELD_EXPERIMENTAL_NPM_OSV_CVSS`]
When `database_specific.severity` is absent and a `severity[]` entry has `type` `CVSS_V3` or `CVSS_V4` and a `score` string, map the numeric score with the documented cuts: 9.0–10 critical, 7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low. A score that does not parse leaves today's severity. Do not invent a vector. Negative: a `database_specific.severity` of `HIGH` wins over a low CVSS score. Flag off, CVSS is ignored, as today. Promotion would be R10 because severity is part of the finding key.

### Phase 246 — alias dedupe [`FULLSHIELD_EXPERIMENTAL_NPM_OSV_ALIAS`]
When two OSV ids share an alias and affect the same `name@version`, emit one `DEPS-VULN-001`. The surviving id is the `MAL-` id if present, otherwise the `GHSA-` id, otherwise the `CVE-` id, otherwise the lexicographic id. The other ids sit on `references`. Negative: two advisories with no shared alias stay two findings. Flag off, both rows remain. Promotion would be R10 because a row disappears.

### Phase 247 — OSV package URL [`FULLSHIELD_EXPERIMENTAL_NPM_OSV_PURL`]
Also send `purl` `pkg:npm/<name>@<version>` (scoped names percent-encode `/` as `%2F` per the purl spec) on the existing OSV querybatch. Same host `api.osv.dev`. Cache key gains the purl. Results that duplicate an id already returned for the name query are deduped by id. Negative: a mocked batch that returns the same id twice yields one finding. `--offline` does not call the network.

### Phase 248 — nested override proposal [`FULLSHIELD_EXPERIMENTAL_NPM_FIX_NESTED`]
When a direct bump cannot clear a transitive advisory, the proposed `package.json` override uses npm's nested key (`parent>child`) for npm, `pnpm.overrides` for pnpm, and `resolutions` for yarn. The version is `minFixedVersion` from the OSV cache only. No fixed version → no proposal. Still unsafe, still does not edit the lockfile, still prints `run npm install`. Negative: a same-major direct bump stays the existing safe proposal and does not add a nested key.

### Phase 249 — SBOM purl qualifier [`FULLSHIELD_EXPERIMENTAL_NPM_SBOM_PURL`]
With the flag on, CycloneDX components for npm packages set `purl` to `pkg:npm/<name>@<version>` and, when integrity is known, add the `checksum` the CycloneDX spec already allows. Scoped purls follow Phase 247's encoding. Flag off, SBOM bytes are unchanged. Negative: a package with no integrity omits the checksum and still has the purl. Validation uses the existing CycloneDX check. This does not add a new finding ID.

### Phase 250 — local npm audit diff [`FULLSHIELD_EXPERIMENTAL_NPM_AUDIT_DIFF`]
`fullshield npm-audit-diff --file <audit.json>` reads a file the user already produced. It does not run `npm`, does not install, and does not fetch. It compares advisory ids in that file with `DEPS-VULN-001` ids from a local `--from` scan JSON, or from the last scan file if `--from` is omitted. It prints ids only in the audit file and ids only in the scan. Exit 0. It does not create findings and does not invent ids that are in neither file. Negative: two files with the same ids print both sets empty. A missing file exits 2 with a new `FS-E` code appended in `docs/errors.md`. An audit file with no version matches nothing and is listed as `unmatched`, not as a new advisory.

---

### 47.4 Order

Build 108 through 250 in numeric order, after phase 107, as Section 45 lists them. Lane D may read Lane C's cache after those phases are merged. It must not fetch a packument itself. Lane E may read Lane D's cache the same way.

### 47.5 Needs human decision before any 108–250 phase is promoted

1. Section 41 items 1–2 on NodeGoat and goof, same precondition as Section 46.
2. Whether any Lane A ID is allowed to become stable. Several of them (missing integrity, non-registry host) will fire on real registries' older lockfiles. Promotion needs a 20-finding sample on `bench/realworld.json` with 0 confirmed false positives, or the ID stays experimental.
3. Phase 245 and Phase 246 change finding keys if promoted. They need an R10 review. Until then they stay flagged.
4. Phase 226's popular list is frozen at the names already in source. Adding names is a human edit.
5. Implementation follows the 1.2.0 order in Section 45. These phases are already in that scope.
