# FullShield — Build Spec for Cursor (full, rev 2026-10-21l)

> Package: `fullshield` on npm (owner `kathan2404`). Repo: https://github.com/kathanp/fullshield (public, MIT).
> Language: TypeScript (strict). Runtime: Node.js ≥ 22.13. Distribution: one npm package (CLI + library + runtime middleware).
> Live on npm: `1.0.1` is latest (published 2026-10-21T02:43:27Z with provenance). `0.1.3` was **published WITHOUT provenance — must never happen again**. Placeholders `0.0.0-stage`, `0.0.1` deprecated. `0.1.2` was never published.
> This file is the only spec. The 2026-10-14 draft (`SECURITY_SCANNER_SPEC (1).md`) is deleted. Its design lives here; Section 33 lists the few requirements that draft stated and this file had shortened. Later text wins where the draft disagreed.
> [X] Complete: phases 1–55 and 57–94. Phase 56 is not in 1.0.1 (blocked on R15). Phase 65 is coded; the 5-second nest/undici target is still unmet. Experimental phases stay off unless their flag is set. Phases 36–45 are reference, not a queue.
> **Current queue is Section 45** for autopilot runs. The 1.2.0 version scope is there. 1.0.1 is published. Section 47 phases 108–250 are in that same 1.2.0 scope, after 107. Section 43 is the finished 2026-10-19 run; Section 42 adds the quality gate (R24, Phase 94) and the definition of done for every remaining phase. During an autopilot run, Section 45 R26 item 4 overrides Section 40.5: no report file is written. Outside a run, Section 40.5 report-file rules still apply. Earlier queue: Section 40 (2026-10-19, lanes A/B/C). Section 36 is the 2026-10-18 record. Leadership phases 76–93 are in Section 39 and are in this tree behind their flags. Advanced phases 60–75 are in Section 37; Phase 47 has an addendum (47.1) there that is part of its acceptance. Section 38 is the production-reliance stance (not a queue). Section 41 lists human-only work. Phase 56 is not in this release.
> Section 48 is a category index of phases 1–250 (reference, not a queue). Section 49 holds phases 251–500, specified in full.

---

## 0. HARD RULES (read first, apply always, no exceptions)

Breaking any rule below = stop work and report to the human. Do not "fix forward" around a rule.

### 0.1 Authority
- [ X ] **R1.** The human approves: tags, publishes, merges to `main`, ground-truth reviews, test edits, threshold changes, and moving any feature from experimental to stable. Cursor never does these without an explicit "go" in the current message. During an autopilot run (Section 45, R26), the human's continuation after `docs/FEATURES.md` (the word `next`, or any later message in that chat) is the go for the rest of that run: commit, push `next`, open the PR, merge to `main`, and tag. It is not a go for `npm publish` or `npm login`. Those commands stay forbidden. The human's other act in that run is approving the staged version on npmjs.com.
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
- any R1 action that R26 does not hand to the agent. Outside an autopilot run, tag, publish, and merge to `main` are never done. Inside an autopilot run, after the features-file continuation, the agent commits, pushes, merges, and tags. The agent never runs `npm publish` or `npm login`. The npmjs.com click stays under "Needs human decision". Ground-truth edits, test edits, threshold changes, and promotions that the approved features file does not name are still never done.

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

An autopilot run follows Section 45 instead of steps 7–9 below. After the features-file continuation the agent opens the PR, merges, and tags. Step 9 stays the human's click on npmjs.com. The agent never runs `npm publish` or `npm login`.

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
| Future | 251–500 | Section 49, specified in full |

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

1. Queue. Section 43 is history for an autopilot run (amends R25).
2. Branches. Work happens on a local run/<name> branch off `next`, with phase worktrees
   wk/test/phase-N and wk/code/phase-N in ../fullshield-wt/ (amends R18 and R21 for
   location only; integration is still one phase at a time, in table order, verify and
   default-scan-diff after each).
3. Two human stops. The agent writes `docs/FEATURES.md` and stops. The human reads it and
   may edit it. The next message in that chat (the word `next`, or any other continuation)
   approves the file on disk. The agent then runs `--approve-features --from-chat` and
   does not stop again for content approval. The second human act is the npmjs.com
   staged-version click. Open D-n marks are decided by the agent and must not be
   left open. The agent writes `R10 approved` only when the approved features file says
   default scan output changes. A default-scan-diff the features file did not name still
   parks (S1).
4. Commits and step 10. run/<name> keeps one `phase-N: <summary>` commit per phase (R19).
   The finished run is squashed into one commit `release: <x.y.z>` on release/<x.y.z>.
   At step 10 the agent fast-forwards that commit onto `next`, opens the PR to `main`,
   merges with a merge commit after the matrix is green, and pushes tag `v<x.y.z>` on
   `origin/main`. That sequence amends R1 and R18, and it amends the R1 session-stop in
   Section 0.7, for those GitHub actions only. `main` still moves only by a PR from
   `next`. R19's "never mix phases in one commit" does not apply to that release commit.
5. Records. No report file, run log, or PROGRESS.md entry is written (replaces Section
   40.5 for the run). R8 still applies: real output is pasted in the chat summary.
6. Publish. The master never runs `npm publish` or `npm login`. The tag push starts
   `.github/workflows/publish.yml`. The human approves the staged publish on npmjs.com
   with 2FA. No provenance means the version stops (S6).
7. One content push. A second push of code is refused. A red GitHub check is not fixed
   by pushing again. If branch protection refuses the merge, the run stops and tells the
   human. The agent does not bypass protection.
8. Still a stop after the features continuation: R3 test edits, R3a, a threshold change,
   a ground-truth edit, or a promotion to stable that the approved features file does not
   name. The agent does not weaken a test to finish the run.
9. Everything else in Section 0 applies unchanged, including R3, R3a, R10, R11, R13,
   R15, R16a, R17, R22, R23, R24 and S1–S7, except the commit, push, merge, and tag that
   item 4 hands to the agent.

### Version scope 1.2.0

Target `1.2.0`, a minor (R16a): every rule ID in Section 46 and Section 47 is new. Definitions stay in those sections. This run does not promote any rule (R11). Section 41 items 1–2 on NodeGoat and goof are not done, so nothing moves to stable and default `scan --json` output does not change (no R10). Phases 108–250 are in this version, after 107.

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
Under AUTOPILOT, this order is the 1.2.0 order.

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

---

## 48. Category Index (reference — not a queue)

This section groups phases 1–250 by what they do. It does not define order, scope, or status. Section 45 is still the only queue (R25, R26). Each phase is listed once, under its primary category. Phases that span two areas name the other area in a note. Status lives in Section 30 and in each phase's own heading. This index does not record status.

### 48.0 Summary

| # | Category | Phases | Count | Share |
|---|---|---|---|---|
| 1 | Core engine, platform, performance | 1, 22, 25, 42, 46, 65, 78, 79, 88 | 9 | 3.6% |
| 2 | SAST (code vulnerabilities) | 4, 5, 13, 27, 28, 29, 40, 50, 51, 53, 57, 64, 75, 80, 81, 90, 95–101, 103, 107 | 25 | 10.0% |
| 3 | Secrets | 2, 30, 69, 82, 105 | 5 | 2.0% |
| 4 | Dependencies & reachability | 3, 11, 39, 52, 54, 55, 56, 61, 62, 63, 104, 106, 108–147, 228–247 | 72 | 28.8% |
| 5 | Supply-chain defense | 19, 31, 70, 86, 87, 148–227 | 85 | 34.0% |
| 6 | Config, IaC, edge, host | 12, 23, 33, 35, 102 | 5 | 2.0% |
| 7 | Runtime protection & live testing | 8, 17, 18, 20, 32, 71, 72 | 7 | 2.8% |
| 8 | AI & LLM-app security | 14, 15, 16, 21 | 4 | 1.6% |
| 9 | Fix & remediation | 7, 24, 48, 49, 91, 248 | 6 | 2.4% |
| 10 | Reporting, CI, integrations, SBOM | 6, 9, 34, 44, 47, 58, 59, 60, 66, 74, 83, 84, 85, 89, 249, 250 | 16 | 6.4% |
| 11 | Evidence, benchmarks, governance | 26, 37, 38, 41, 43, 67, 68, 73, 76, 77, 93 | 11 | 4.4% |
| 12 | Release, quality, self-security | 10, 36, 45, 92, 94 | 5 | 2.0% |
| | **Total** | | **250** | |

Sub-phases 26b, 26c and the NoSQL change (Section 25) belong to category 2 and are not counted separately.

---

### 48.1 Core engine, platform, performance (9)
What the scan runs on: file walking, orchestration, platforms, speed, and the dev loop.

| Phase | Name | Flag |
|---|---|---|
| 1 | Scaffold, Finding model, config, walker | stable |
| 22 | Threat model, incremental, workspaces, dashboard | `PLATFORM` |
| 25 | Windows + lazy SQLite | stable |
| 42 | Performance harness, worker parse pool | stable |
| 46 | Supported runtime floor (Node ≥ 22.13) | stable |
| 65 | Taint function summaries (5 s target unmet) | `TAINT_SUMMARIES` |
| 78 | Cold-scan performance v2 | `PERF2` |
| 79 | Time budget and partial results | `BUDGET` |
| 88 | `fullshield dev` watch loop | `DEV` |

### 48.2 SAST — code vulnerabilities (25)
Taint engine, rule classes, framework sources, and precision work on code findings.

| Phase | Name | Flag |
|---|---|---|
| 4 | SAST engine + SQLI, CMDI, PATH, EVAL, JWT, CRYPTO | stable |
| 5 | Remaining SAST rules (+ config module) | stable |
| 13 | Cross-file taint (also reachability + SBOM) | stable |
| 27 | ORM raw SQL, template-literal shell gaps | `SAST_GAPS` |
| 28 | Next.js / NestJS / Hono / Koa sources | `FRAMEWORKS` |
| 29 | New classes (ReDoS, deser, XXE, CSRF, …) | `CLASSES` |
| 40 | Taint engine v2 | `TAINT_V2` |
| 50 | Template-engine-aware XSS (Swig) | R10 |
| 51 | Cross-file returns | R10 |
| 53 | Validation inference (zod/joi/class-validator) | `VALIDATION` |
| 57 | Custom rules (schema) | `CUSTOM_RULES` |
| 64 | Config-declared sources and sanitizers | `CUSTOM_SANITIZERS` |
| 75 | Router-level auth inheritance | R10 |
| 80 | Type-aware receiver resolution | `TYPES` |
| 81 | Library model packs | `MODELS` |
| 90 | User-supplied Semgrep-style rules | `SEMGREP_RULES` |
| 95 | Disabled TLS verification | `TLS` |
| 96 | Crypto v2 (ECB, IVs, RSA, JWT expiry) | `CRYPTO2` |
| 97 | Server-side template injection | `SSTI` |
| 98 | Secrets written to logs | `LOGLEAK` |
| 99 | Unverified webhooks | `WEBHOOK` |
| 100 | Session fixation | `SESSION2` |
| 101 | Browser-side JS (DOM XSS, React, postMessage) | `BROWSER` |
| 103 | Next.js server boundary (also config + secret) | `NEXT` |
| 107 | Ownership-check (IDOR) hints | `IDOR` |

### 48.3 Secrets (5)

| Phase | Name | Flag |
|---|---|---|
| 2 | Secrets module, masking, `--staged` | stable |
| 30 | History, bundle, `--verify-secrets` | `SECRETS_ADV` |
| 69 | Rotation playbooks (docs only) | — |
| 82 | Offline structure/checksum checks | `SECRET_CHECK` |
| 105 | Committed credential files | `CREDFILES` |

### 48.4 Dependencies & reachability (72)
Lockfiles, OSV, reachability, the dependency graph, and advisory handling.

| Phase | Name | Flag |
|---|---|---|
| 3 | Lockfile parsers, OSV batch, cache, offline | stable |
| 11 | `watch` (new OSV only) | stable |
| 39 | Reachability v2 (symbol-level) | stable |
| 52 | Phantom and mismatched deps | R10 |
| 54 | Per-workspace lockfiles | `WORKSPACES` |
| 55 | Runtime-observed reachability | `OBSERVED_REACH` |
| 56 | Exploit prioritization (EPSS/KEV) — **blocked on R15** | `EXPLOIT_INTEL` |
| 61 | Reachability evidence | `REACH_EVIDENCE` |
| 62 | Lockfile PR diff | `DEPS_DIFF` |
| 63 | Modern lockfile formats (yarn berry, pnpm v9, bun) | `LOCKFILES` |
| 104 | Vendored library versions | `VENDORED` |
| 106 | Unmaintained + unfixed deps | `HEALTH` |
| 108–127 | npm Lane A — lockfile truth (20) | `NPM_*` |
| 128–147 | npm Lane B — manifest and project policy (20; 136 and 142 are `CONFIG-*` IDs) | `NPM_*` |
| 228–242 | npm Lane G — graph and reachability (15) | `NPM_*` |
| 243–247 | npm Lane H — advisory fidelity (OSV range, withdrawn, CVSS, alias, purl) (5) | `NPM_*` |

### 48.5 Supply-chain defense (85)
Signals that a package itself is hostile or tampered with, beyond known advisories.

| Phase | Name | Flag |
|---|---|---|
| 19 | Supply-chain defense + install-guard | `SUPPLY` |
| 31 | Worm/workflow indicators, overrides, VEX | `VEX` |
| 70 | Stealer, chain-C2, platform-gate, security-placeholder | `SUPPLY` |
| 86 | Dependency capability profile and diff | `CAPABILITIES` |
| 87 | Provenance and maintainer change signals | `PROVENANCE` |
| 148–167 | npm Lane C — registry packument (20) | `NPM_REG_*` |
| 168–187 | npm Lane D — tarball bytes (20) | `NPM_TARBALL_*` |
| 188–207 | npm Lane E — lifecycle scripts (20) | `NPM_SCRIPT_*` |
| 208–227 | npm Lane F — package names (20; 226 and 227 emit no finding) | `NPM_*` |

### 48.6 Config, IaC, edge, host (5)

| Phase | Name | Flag |
|---|---|---|
| 12 | `edge` posture check | stable |
| 23 | Compliance mapping + light IaC | `COMPLIANCE` / `IAC` |
| 33 | MCP client/server config | `MCPCFG` |
| 35 | Host OpenSSH exposure | `HOST` |
| 102 | Electron hardening | `ELECTRON` |

Config rules in the stable `config` module were built in Phase 5 (category 2).

### 48.7 Runtime protection & live testing (7)

| Phase | Name | Flag |
|---|---|---|
| 8 | Express/Fastify middleware, rate limiter | stable (monitor) |
| 17 | RASP sink hooks + `--import` | `RASP` |
| 18 | Virtual patches, egress, honeytokens, threat response | `VPATCH` / `HONEY` |
| 20 | Exploit confirm + fuzz + IDOR (localhost only) | `CONFIRM` |
| 32 | Response DLP | `DLP` |
| 71 | RASP sink coverage | `RASP` |
| 72 | RASP DNS pin store | `RASP` |

### 48.8 AI & LLM-app security (4)

| Phase | Name | Flag |
|---|---|---|
| 14 | AI provider layer, redaction, cost cap | `--ai` |
| 15 | AI explain + verified fix | `--ai` |
| 16 | AI logic hunter + anomaly baseline (internal only) | `AI_INTERNAL` |
| 21 | MCP server + LLM-app rules | `MCP` / `LLM` |

### 48.9 Fix & remediation (6)

| Phase | Name | Flag |
|---|---|---|
| 7 | Fix engine (`fix`, `fix --apply`) | stable |
| 24 | Remediation agent (localhost only) | `AGENT` |
| 48 | Unused dependency removal | stable |
| 49 | Upgrade plan | stable |
| 91 | Fix verification | `FIX_VERIFY` |
| 248 | Nested override proposal | `NPM_FIX_NESTED` |

### 48.10 Reporting, CI, integrations, SBOM (16)

| Phase | Name | Flag |
|---|---|---|
| 6 | SARIF/MD/HTML, `--fail-on`, baseline, suppression | stable |
| 9 | `init`, notifiers | stable |
| 34 | Policy-as-code + PR summary | `POLICY` |
| 44 | Developer experience (console, doctor, FS-E codes) | stable |
| 47 | Actionable console view | stable |
| 58 | Route security map | `ROUTES` |
| 59 | GitHub Action wrapper | — |
| 60 | Offline finding explainer | `EXPLAIN` |
| 66 | Reachability in SBOM and VEX | `SBOM_REACH` |
| 74 | SARIF v2 fields | `SARIF_V2` |
| 83 | External findings ingest and dedupe | `INGEST` |
| 84 | Deterministic priority score | `PRIORITY` |
| 85 | Attack paths | `PATHS` |
| 89 | SPDX SBOM | `SPDX` |
| 249 | SBOM purl qualifier | `NPM_SBOM_PURL` |
| 250 | Local npm audit diff | `NPM_AUDIT_DIFF` |

### 48.11 Evidence, benchmarks, governance (11)
Dev tooling only. Not in the tarball unless the phase says so.

| Phase | Name |
|---|---|
| 26 | Public benchmark harness |
| 37 | Benchmark governance (holdouts, review sheets) |
| 38 | Competitive benchmark |
| 41 | Precision pass (real-world corpus) |
| 43 | Experimental → stable promotion criteria |
| 67 | Human review CLI |
| 68 | Holdout freeze and one-shot run |
| 73 | Promotion evidence batch 1 |
| 76 | Precision sampling harness |
| 77 | Real-world precision regression gate |
| 93 | Promotion evidence batch 2 |

### 48.12 Release, quality, self-security (5)

| Phase | Name |
|---|---|
| 10 | README, rule docs, CHANGELOG, publish config |
| 36 | Release integrity (provenance gate, diff, semver, pack budget) |
| 45 | Self-security hardening (pinned actions, Scorecard, CodeQL) |
| 92 | Repository hygiene (issue templates, branch-protection doc) |
| 94 | Quality gate (R24) |

### 48.13 Notes on the distribution
- Categories 4 and 5 hold 157 of 250 phases. 143 of them (108–250) are in the 1.2.0 scope.
- Secrets, config/IaC, and release each have 5 phases.
- Category 11 has 11 phases, but the human-only items in Section 41 still decide whether any number in it can be cited.

---

## 49. Phases 251–500

Phases 1–250 mostly add rules on top of a few engines: taint, reachability, the registry/tarball cache, and the finding pipeline. A rule cannot be more precise than the engine under it. Phases 251–500 deepen those engines and the work built on them.

Phases 251–500 are specified in full in this section.

**Autopilot rule:** autopilot does not rewrite, shorten, or replace a phase in this section. A phase whose text is still missing a flag, an acceptance check, or a false-positive paragraph is not buildable, and autopilot parks it instead of inventing the missing text.

**Precondition (R1):** Section 41 items 1–2 are done for NodeGoat and goof before any phase here is promoted. Phases may be built before that, behind their flags. Without reviewed numbers, none of them can claim a gain.

**Rules for every phase from 251 to 500** (on top of Section 0, 39.1 and 42.1):
- Each phase sits behind its own `FULLSHIELD_EXPERIMENTAL_<NAME>` flag. With the flag off, `scan --json` is byte-identical on every fixture, bench app and realworld repo.
- **Replacement phases (251, 252, 253, 254, 256, 257, 269) first reach byte-identical output against the old engine with the flag on, before any behavior change.** A behavior change is a second, separately reviewed step that produces a `DIFF.txt` (R10). The same applies to any later phase that changes findings: prove byte-identical output with the new code present but disabled, then change behavior in a second step.
- A phase that needs the IR (251) is not started before 251 reaches byte-identical output.
- No new hard dependency (R13). No new network host (R15). No ML scoring, no telemetry, no LLM in the request path, nothing that attacks a non-local host (Section 31).
- JS/TS only (Section 4.3).
- No new finding rule ID unless the phase says so.
- Every number goes into `bench/deep/<phase>.json` from a stored run, labeled reviewed or unreviewed (R7).
- Fixtures are written from scratch (B8). Malware-shaped fixtures are inert and use `example.invalid`.
- Phases that read npm data reuse `NpmFacts` (261) and its cache. They never fetch on their own.

**Dependency order:**

```
251 IR ─┬─ 252 heap ── 253 context ── 254 async
        ├─ 256 labels ── 258 guards
        ├─ 257 types (needs 80)
        ├─ 255 routes
        ├─ 262 evidence ── 263 diff-testing
        └─ 269 incremental ── 270 scale
259 dep call graph (needs 228, 233) ── 260 advisory symbols
261 npm engine unify (independent)
264 metamorphic (needs 251) ── 265 precision gate (needs 76 labels)
266 corpus (independent)
267 shared sink catalog (needs 251, 71) ── 268 runtime feedback (needs 55, 259)
```

Build order for the specified phases: 261, 266, 251, 256, 252, 253, 254, 255, 257, 258, 262, 264, 259, 260, 263, 265, 267, 268, 269, 270, then 271 through 290 in numeric order. Phases 271–290 need 251–258.

Phases 291–310 lower frameworks into the 251 IR and the 255 route model. They do not start before 251 is byte-identical. Phases 311–330 need 255 and 307. Phases 331–345 need 256. Phases 346–380 need 261 and read only `NpmFacts` or local files. Phases 381–405 need 267, ship in the runtime entry, and import no scanner code (R14). Phases 406–425 need 262. Phases 426–450 add experimental output fields and do not change the default finding key. Phases 451–465 read text the repo already contains. Phases 466–500 are dev tooling, are not packed (Q12), and do not scan a holdout app inside the phase commit (B3).

### 49.0 Analysis contract (binds 251–500)

Later phases are transfer functions on three objects. A phase that walks the AST on its own, keeps a private taint bit, or prints a score is wrong.

1. **IR (251).** One SSA-like representation of the program. A framework, ORM, template, queue, or CI file becomes IR edges: sources, sinks, calls, route records, and auth predicates. After 251 is on, stable SAST rules are queries. They do not reimplement flow.
2. **Witness (262).** A finding carries a replayable witness: files, lines, IR ops, labels at the sink, sanitizers that removed labels, and guards that failed to. `scripts/verify-proof.mjs` re-derives the witness from the cited files and does not import the engine. A finding whose witness fails is a bug, not a result. Phases before 262 still attach the witness object; the checker runs when 262 is on.
3. **Fuel and soundness (271).** Fixpoints, points-to, and partial evaluation spend fuel. Exhaustion writes `unsoundEvent { kind, file, line, reason }` from the closed enum and over-approximates in `sound` mode. It does not call `eval`, `vm`, or `Function`. It does not execute the program and it does not open a network connection (R15).

The value domain is a product, not a boolean and not a learned score (Section 31, Phase 84):

```
Effect = Origin × LabelSet × CharClass × AccessPath × MustMay × Privilege
```

Join is union on may-facts and intersection on must-facts. Severity stays the documented table for that rule. Origins used below: `request`, `stored`, `session`, `cache`, `queue`, `event`, `cli`, `environment`, `principal`, `tenant`, `secret`, `jwt-header`, `gha-event`. A new origin is added only by the phase that names it.

Queries from 272 on are demand-driven from sinks (tabulation over the IR). A scan that asks about SQL does not build the HTML context.

Flag off, `scan --json` is byte-identical. A phase that can change a finding key first lands with the new code disabled and output identical, then changes behavior in a separately reviewed step that writes `DIFF.txt` (R10). That split is part of the phase, not a follow-up someone might skip.

Shipped files do not claim exclusivity, rank, or completeness (Section 4.4, Section 31). The mechanism is the spec. The measurement is a stored run labeled `unreviewed` until a human reviews it (R7).

### Phase 251 — Unified dataflow IR [`FULLSHIELD_EXPERIMENTAL_IR`]
Today taint is spread across several AST walkers: intra-function taint, cross-file taint, taint v2, and the Phase 65 summaries. Replace them with one intermediate representation.

Build:
1. Lower each function to an IR of `assign`, `call`, `return`, `phi`, `property-load`, `property-store`, `await`, and `branch(cond)`. Values are SSA-numbered. Source location is kept on every node.
2. A module-level IR links imports to exports through the existing resolver: TS paths, barrels, exports maps.
3. All stable SAST rules are re-expressed as `source → sink` queries over the IR. Rule files declare sources, sinks, and sanitizers as data, using the Phase 81 schema.
4. The IR is cached per file under the parse cache, keyed by content hash + version + config hash. A corrupt entry is discarded.

Acceptance: with the flag on, default `scan --json` is byte-identical to the flag-off engine on vulnerable-app, clean-app, all bench apps, and all realworld repos. Every SAST rule has a test that runs it once on the old engine and once on the IR. Mutation smoke (Q10) passes on IR-backed rules. Peak RSS and cold time on the Next.js sample are no worse than 110% of the stored Phase 78 run.

FP risk: none by construction while the output is identical. This phase changes architecture, not findings.

### Phase 252 — Field-sensitive heap model [`FULLSHIELD_EXPERIMENTAL_HEAP`]
Track taint per access path (`obj.a.b`, `arr[*]`, `map.get(k)`) instead of per variable, with a configurable path depth limit (default 3, then collapse to the base).

Build: path-indexed taint sets on `property-load` / `property-store`. Spread, `Object.assign`, destructuring, and rest/spread arguments copy paths. Array methods (`map`, `filter`, `find`, `reduce`, `forEach`) carry element taint. `Map`/`Set` use a coarse `*` key.

Acceptance: positive fixture: `const o = { safe: 1, bad: req.query.x }; db.query(sql + o.bad)` → finding. Negative fixture: same object with `db.query(sql + o.safe)` → no finding, where the old engine reported one. Report every removed key on tuning apps as `seen`, unreviewed, in `DIFF.txt` (R10 step).

FP risk: under-taint when the path limit collapses. A fixture at depth 4 documents that the collapse keeps the taint (sound side), not drops it.

### Phase 253 — Context-sensitive summaries [`FULLSHIELD_EXPERIMENTAL_CONTEXT`]
Replace the hard depth-5 hop limit with function summaries computed to a fixpoint, using one level of call-site sensitivity (k=1).

Build: each function gets a summary `param_i → return`, `param_i → sink(class)`, `param_i → param_j.field`. Summaries are computed bottom-up over the call graph with a worklist. Recursion and strongly connected components iterate to a fixpoint with a cap of 10 rounds; past the cap, the summary is "all params flow everywhere" (sound). Call-site sensitivity distinguishes `helper(req.body.x)` from `helper("literal")` at the same callee.

Acceptance: a fixture with a 7-hop chain across 4 files is found (the old engine stops at 5). A fixture where one callee is called with a tainted and a literal argument reports only the tainted call site. A recursive fixture terminates. The time budget on nest/undici is no worse than the Phase 65 stored run.

### Phase 254 — Async and event flow [`FULLSHIELD_EXPERIMENTAL_ASYNCFLOW`]
Model flows that the IR otherwise breaks at.

Build: `await` and `.then(cb)` pass the resolved value. `EventEmitter.emit(name, v)` → `on(name, (x) => …)` when the emitter object and event name are both statically resolvable. Streams: `pipe` and `pipeline` carry taint from a readable built from request input. Callbacks into known library APIs (from model packs) pass arguments to the callback's parameters. `setImmediate` / `queueMicrotask` / `process.nextTick` carry closure taint.

Acceptance: positive fixture per construct. Negative: emit and listen on different event names; an emitter whose identity cannot be resolved produces no cross-handler flow (documented gap, not a guess).

### Phase 255 — Unified route model [`FULLSHIELD_EXPERIMENTAL_ROUTEMODEL`]
Today route knowledge is split across AUTH (75), routes (58), IDOR (107), attack paths (85), webhooks (99), and frameworks (28). Build one model all of them read.

Build: a `Route` record of `{ method, fullPath, file, line, handlerFn, middlewareChain[], authState: present|absent|unknown, validators[], framework }` built once per scan from Express, Fastify, Koa, Hono, Nest, and Next. Mount prefixes, router nesting, and cross-file routers are resolved through the IR module graph.

Acceptance: each consumer phase gets a test asserting it reads the shared model, and each consumer's existing tests pass unchanged. A fixture with three nested routers across three files produces the correct `fullPath` and the inherited auth state.

### Phase 256 — Per-class taint labels [`FULLSHIELD_EXPERIMENTAL_LABELS`]
Replace boolean taint with a set of labels: `{sqli, nosqli, cmdi, path, xss, ssrf, redirect, eval, ssti, log}`. Sources carry all labels. Sanitizers remove only the labels they handle. Validators refine the value type: `isInt`, `Number()`, and `z.number()` remove every string-injection label at once.

Build: sanitizer and validator semantics move into model packs as `removes: [labels]` / `refines: type`. The Section 6.2 rules become data: `encodeURIComponent` removes `redirect`/`ssrf-path` only, and `DOMPurify` removes `xss` only.

Acceptance: table-driven tests run every sanitizer against every sink class (a matrix of about 30 sanitizers × 10 classes), each cell asserting the expected kept or removed result. Fixture: an HTML-escaped value reaching SQL still reports. Fixture: `Number(req.query.id)` into SQL concatenation does not report. Removed or added keys go to a `DIFF.txt` (R10).

### Phase 257 — Types on the IR [`FULLSHIELD_EXPERIMENTAL_IRTYPES`]
Move Phase 80's type checker results onto IR values so every rule uses them, not only receiver resolution.

Build: attach the TS type to each IR value when a program is available. Uses: (a) sink receiver resolution (Phase 80); (b) a value typed `number`, `boolean`, or a literal union drops string-injection labels (256); (c) the interface method a call targets resolves to the implementing class when there is exactly one implementation in the program.

Acceptance: the Phase 80 fixtures pass through the IR path. A new fixture: `function get(id: number) { db.query("… " + id) }` called from a route with `Number(req.params.id)` → no finding. Same with `id: string` → finding. `any` keeps today's behavior.

### Phase 258 — Guard recognition [`FULLSHIELD_EXPERIMENTAL_GUARDS`]
Prune flows that a dominating guard makes safe. This is not full path sensitivity, just a fixed set of recognized guard shapes.

Build: recognize a dominating guard on the same value before the sink, where the failing branch returns or throws. Shapes:
- `allowlist.includes(x)` with a literal array
- `x === 'a' || x === 'b'`
- `/^[a-z0-9_-]+$/.test(x)` with an anchored regex that excludes the dangerous characters for that sink class
- `path.resolve(base, x).startsWith(base + path.sep)`
- `typeof x === 'number'`

Guards clear only the labels they make impossible. An unanchored regex is not a guard.

Acceptance: positive and negative fixture per guard shape. The negative cases are: a guard on a different variable, a guard in a non-dominating branch, an unanchored regex, and `startsWith(base)` without `path.sep` (the known prefix bug, still reported).

FP risk: a guard that looks safe but is not. The anchored-regex check is conservative: any character class that admits a sink metacharacter keeps the label.

### Phase 259 — Call graph into node_modules [`FULLSHIELD_EXPERIMENTAL_DEPGRAPH`]
Extend reachability across the dependency boundary: does the app's call into `express` eventually reach the vulnerable function in `qs`?

Build: parse installed packages statically (never execute, R15), lazily, only along paths from an imported direct dependency to a package with an advisory that names functions (OSV `affected_functions` or Phase 260 data). Build package-level summaries `export → reaches(pkg.fn)` with a depth cap of 3 packages, cached by package integrity. New reachability class `function-reachable-via-dependency`, flag-only.

Acceptance: a fixture `node_modules` with app → `a.handle()` → `b.parse()` (vulnerable) reports `function-reachable-via-dependency` with the full call path. The same tree where `a` never calls `b.parse` reports `reachable-via-dependency` (today's class), not a downgrade. A test asserts no downgrade is ever made from this phase. It only upgrades confidence or adds evidence. Malicious packages are never touched.

### Phase 260 — Advisory symbol data [`FULLSHIELD_EXPERIMENTAL_ADVSYMBOLS`]
Most OSV npm advisories do not list affected functions, so symbol reachability (39) rarely runs.

Build: `models/advisory-symbols.json` with rows `{ osvId, package, affectedExports[], source: <patch commit URL>, reviewed: false }`. Only the human sets `reviewed: true`. Rows with `reviewed: false` are used only under this flag and are labeled `unreviewed` on the finding. A script `scripts/advisory-symbols-candidates.mjs` lists the top 100 advisories by hit count across the bench and realworld corpus for the human to fill in. It never fills a row itself (R6: never invent vulnerability data).

Acceptance: a schema test rejects rows without a `source`. A test asserts Cursor-authored commits never set `reviewed: true` (same guard as Phase 67). One hand-written fixture row drives a `symbol-not-called` result in a fixture app.

### Phase 261 — npm check engine and flag collapse [`FULLSHIELD_EXPERIMENTAL_NPM_GROUPS`]
Phases 108–250 add 143 flags and repeat the same fetch, cache, and parse code.

Build: one `NpmFacts` layer computed once per scan: lock rows, manifest, `.npmrc`, packument cache, tarball cache, script text, names, graph. Every 108–250 check becomes a pure function `(NpmFacts) → Finding[]`. Add 8 group flags, one per Section 47 group (`NPM_LOCK`, `NPM_MANIFEST`, `NPM_REGISTRY`, `NPM_TARBALL`, `NPM_SCRIPTS`, `NPM_NAMES`, `NPM_GRAPH`, `NPM_ADVISORY`). Each per-phase flag stays as an alias for one minor release with a deprecation note.

Acceptance: for every 108–250 rule ID, its output under its old flag equals its output under its group flag (generated test). A counter test asserts each packument and each tarball is fetched at most once per scan. Q5 API snapshot diff listed. Minor bump (R16a).

### Phase 262 — Machine-checkable evidence [`FULLSHIELD_EXPERIMENTAL_PROOF`]
Each finding carries enough data to re-check it without trusting the engine.

Build: `proof: { source: {file,line,col,kind}, sink: {file,line,col,class}, steps: [{file,line,op}], labelsAtSink: [...], sanitizersSeen: [{fn, removed: [...]}], guardsSeen: [...] }`. `scripts/verify-proof.mjs` re-parses only the cited files and checks each step exists and connects (each step's value is used by the next). A finding whose proof fails verification is a bug, not a result.

Acceptance: every SAST finding on vulnerable-app and all bench apps has a proof that verifies. A deliberately corrupted proof fails. The verifier imports no engine code (separate implementation, so it can catch engine bugs).

### Phase 263 — Differential testing against Semgrep CE (dev tooling)
Turn disagreements with another engine into a triage queue.

Build: on tuning apps and the realworld corpus, run pinned local Semgrep CE with public rulesets (no account, R15 not involved since it runs locally; never bundle its rules, Section 31). Map findings to B4 classes. Export three sets: both-found, only-FullShield, only-Semgrep. Each disagreement gets the cited code and both traces into `bench/diff/<app>.todo.json` with `label: null`.

Acceptance: deterministic export for a fixed pin. Labels stay null (human-only). No claim about Semgrep accuracy in any shipped file.

### Phase 264 — Metamorphic testing [`dev tooling`]
Semantically equal code must give the same finding.

Build: `scripts/metamorph.mjs` takes each positive SAST fixture and generates variants. Transforms:
- rename variables
- split the flow across 2 or 3 files
- wrap it in a helper
- convert the callback to async/await
- inline or extract a constant
- swap string concat for a template literal
- add dead code
- re-export through a barrel

Each variant must report the same class at the moved sink line. Each failure is written to `bench/metamorph/failures.json` as an engine gap with the transform name.

Acceptance: a gap report exists for every SAST rule. The test suite runs a fixed seed subset in CI (non-blocking at first). A transform that changes semantics is a test bug, documented and removed. Variants never enter the default fixture set (R3).

### Phase 265 — Precision gate per rule (CI)
Once humans have labeled samples (Phase 76), stop rules from silently getting worse.

Build: `scripts/precision-gate.mjs` reads human labels and computes the Wilson 95% lower bound per rule. The rule's committed floor lives in `quality/precision-floors.json`, which is human-owned (R1). A rule whose bound drops below its floor fails CI on `next`. A rule with fewer than 20 labels is `ungated` and listed.

Acceptance: fixture labels drive pass, fail, and ungated cases. A test asserts the script never writes the floors file. Note: this gate is inactive until Section 41 item 2 is done, and says so on every run.

### Phase 266 — Real-world corpus v2 (dev tooling)
10 repos are too few to measure false positives.

Build: `bench/realworld.json` grows to 50 pinned repos, stratified by Express, Fastify, Nest, Next, Koa/Hono, monorepos, and Electron, plus 5 TS-heavy and 5 JS-only. Per repo, record crashes, time, peak RSS, and finding count per rule, with all flags off and then each group flag on. Store in `bench/realworld-v2.json`.

Acceptance: repos are cloned at their pins, never executed, never installed. Any crash is a P0 issue logged with the repo and file. The finding-count table feeds Phase 76 sampling.

### Phase 267 — Shared sink catalog [`FULLSHIELD_EXPERIMENTAL_SINKCATALOG`]
Static rules and RASP hooks describe the same sinks in two places.

Build: `models/sinks.json`, the single catalog `{ package, member, argIndex, class, staticSupported, runtimeHook }`. SAST sink matching and RASP hook installation both read it. A consistency test fails when a static sink has no runtime hook and no documented `runtimeGap` reason, or the reverse.

Acceptance: RASP corpus results are unchanged. Static output is byte-identical. The gap list is generated into `RASP-SINKS.md`.

### Phase 268 — Runtime-confirmed reachability [`FULLSHIELD_EXPERIMENTAL_RUNTIMEREACH`]
Combine Phase 55's observed loads with the 259 graph.

Build: when the local `observed-reach.json` shows a vulnerable function's module loaded and its export was called (a call counter in the register hook, names only, no arguments), mark the finding `runtime-observed`. The file stays local and never leaves the machine (R15, test asserts no network). Absence of an observation never downgrades a finding, because a test run is not full coverage.

Acceptance: a fixture app run through the hook in a test produces `runtime-observed` for the called path and nothing for the uncalled one. Hook failure fails open.

### Phase 269 — Incremental IR with dependency tracking [`FULLSHIELD_EXPERIMENTAL_INCR2`]
Build: a query-based engine (Salsa-style). Each derived fact (file IR, function summary, route model, reachability edge) records which inputs it read. A file edit invalidates only the facts that depend on it. Summaries whose output hash did not change stop invalidation from spreading further.

Acceptance: output identical to a cold scan after a sequence of 20 scripted edits on a bench app. Stored `--changed` p50 on nest and undici at or under 2 s (the Phase 42 target was 5 s). If unmet, store the numbers and update Section 28.

### Phase 270 — Memory-bounded monorepo mode [`FULLSHIELD_EXPERIMENTAL_SHARDS`]
Build: for repos above a configurable size (default 500k LOC), split IR construction by workspace into shards on disk. Summaries cross shard boundaries through exported-function summaries only. Peak RSS is capped by `scan.maxMemoryMb` (default 1536); above the cap, shards are evicted least-recently-used.

Acceptance: a synthetic 1M-LOC fixture (generated at test time, not committed) completes under the cap with output identical to an unsharded run on a smaller sample. Next.js realworld peak RSS goes down versus the stored Phase 78 run.

### Phase 271 — Soundness mode and report [`FULLSHIELD_EXPERIMENTAL_SOUNDNESS`]
Every analysis makes approximations. Today they are silent. Make them visible.

Build:
1. Every place the engine gives up records an `unsoundEvent { kind, file, line, reason }`. Places include dynamic property names, `eval`'d code, unresolved imports, depth caps, fixpoint caps, unknown callees, and `Proxy`. Kinds come from a closed enum in `src/engine/unsound.ts`.
2. `scan --soundness-report` writes `.fullshield/soundness.json` with counts per kind and per file, plus the top 50 files by event count.
3. `scan.mode: "precise" | "sound"`. `precise` keeps today's behavior: an unknown callee drops taint. `sound` keeps taint through unknown callees. `sound` is expected to add findings and is never the default.

Acceptance: a fixture per event kind produces exactly that event. `precise` mode output is byte-identical to the flag off. `sound` mode on vulnerable-app reports a superset of `precise` findings (test asserts the subset relation). The report lists file paths only, never code snippets.

FP risk: `sound` mode is noisy by design. It is documented as a research and audit mode.

### Phase 272 — Points-to analysis [`FULLSHIELD_EXPERIMENTAL_POINTSTO`]
Know which objects a variable can hold, so that `db.query`, `this.repo.find` and `service[method]()` resolve to real targets.

Build:
1. Inclusion-based (Andersen-style) points-to on the IR, field-sensitive to the Phase 252 path limit, context-insensitive in the first version.
2. Abstract objects are allocation sites: `new X()`, object literals, `require()` results, factory-call return sites.
3. Constraint solving uses a worklist with cycle collapsing. There is a node budget (default 2M constraints). Past the budget, affected variables point to `unknown` and log a 271 event.
4. Library objects come from model packs (81). `require('pg')` → `Pool` allocation; `pool.query` → sink.

Acceptance: fixtures where a SQL client is passed through two constructors and stored on `this` resolve to the sink. A plain object with a `query` method does not. Budget overflow produces `unknown` plus an event and no crash. Nest and undici cold time stays within 120% of the stored Phase 78 run, measured and stored.

FP risk: merged allocation sites (one factory returning both a safe and an unsafe object). The fixture documents it. 274 and later context sensitivity reduce it.

### Phase 273 — Points-to call graph [`FULLSHIELD_EXPERIMENTAL_CGPT`]
Replace name-based callee guessing with targets from 272.

Build: for each call site, targets = functions in the points-to set of the callee expression. Handles `obj.method()`, `fn.call/apply/bind`, callbacks stored in arrays or maps, handler tables (`handlers[type](req)` when the key set is a finite literal union) and default exports. An unresolved call with no targets is a 271 event, not a silent skip.

Acceptance: a handler-table fixture with a literal key set resolves every entry. A computed key from request input resolves to all entries and logs an event. Call-graph edge counts on the bench apps are stored before and after. Every SAST finding gained or lost goes to `DIFF.txt`.

### Phase 274 — Class hierarchy and prototype chains [`FULLSHIELD_EXPERIMENTAL_CHA`]
Build:
1. ES classes: `extends`, `super` calls, overridden methods, static methods and class fields.
2. Prototype-based code: `Fn.prototype.m = …`, `Object.create(proto)`, `util.inherits` and `Object.setPrototypeOf` with static arguments.
3. A virtual call on a receiver whose points-to set is a class resolves to the most-derived implementations in that set only.
4. Mixins via `Object.assign(Target.prototype, mixin)`.

Acceptance: fixtures cover a base repository class with a safe `find` and a subclass that overrides with raw SQL, called through a base-typed variable holding the subclass (finding) and holding the base (no finding). The `util.inherits` and mixin fixtures each resolve.

### Phase 275 — Closure capture [`FULLSHIELD_EXPERIMENTAL_CLOSURES`]
Nested closures are a documented miss (README Known limitations).

Build: closures capture the enclosing environment by reference. Captured variables become heap cells, so a write in the outer function after the closure is created is visible inside it. Covers immediately-invoked functions, returned closures, closures stored on objects, and closures passed to `setTimeout` or event handlers (with 254). Loop-variable capture follows `let` versus `var` scoping.

Acceptance: fixtures cover
- a closure created before the outer variable is tainted, then called (finding);
- a closure capturing a variable that is reassigned to a literal before the call (no finding when flow-sensitive ordering proves it, otherwise a finding plus a 271 event);
- `var` in a loop versus `let` in a loop.

The README Known-limitations line is updated only after `DIFF.txt` approval.

### Phase 276 — Generators and iterators [`FULLSHIELD_EXPERIMENTAL_GENERATORS`]
Build: `yield v` flows to the `next().value` and `for…of` binding at call sites of that generator. `yield*` delegates. Async generators combine with 254. Built-in iterators: `Array.from`, spread, `Object.entries` / `values` / `keys` (keys carry key taint from objects whose keys came from input), `Map` / `Set` iteration and destructuring from iterators.

Acceptance: a generator that yields `req.query` fields consumed by `for await` into a SQL sink gives a finding. A generator that yields literals gives none. `Object.keys(req.body)` used as a column name reaches SQL with the `sqli` label (identifier position, see 279).

### Phase 277 — Proxy, Reflect, defineProperty [`FULLSHIELD_EXPERIMENTAL_REFLECT`]
These are the main ways JS hides flows. The goal is to model the static cases and report the rest, not to resolve everything.

Build:
1. `Reflect.get/set/apply/construct` with static arguments map to normal IR operations.
2. `Object.defineProperty(o, 'k', { get })` with a static key maps to a getter call on load.
3. `new Proxy(target, handler)` with handler traps declared inline is modeled. Any other proxy marks the object `opaque` and logs a 271 event.
4. `with` statements and `Function.prototype.toString` tricks are always events.

Acceptance: fixtures per modeled construct. An opaque-proxy fixture produces an event and keeps taint in `sound` mode only. No crash on any construct in the Phase 266 corpus.

### Phase 278 — String abstract domain [`FULLSHIELD_EXPERIMENTAL_STRDOMAIN`]
Today taint says only that tainted data is in the string. Injection depends on where it sits.

Build: an abstract string value is a sequence of segments: `literal("…")`, `tainted(labels, charClass)` and `unknown`. Concat, template literals, `join`, `replace` with literal patterns, `slice` / `substring` (to a widened result) and `toLowerCase` / `toUpperCase` update the segments. `charClass` tightens through validators (`/^\d+$/` → digits) and coercions (`Number()` → numeric). Widening after N=8 segments merges into `unknown` with labels kept. Loops widen at the loop head.

Acceptance: unit tests per string operation, with the abstract result compared to a table. A loop that concatenates input terminates and keeps labels. This phase changes no findings by itself; 279–283 consume it. Output byte-identical.

### Phase 279 — SQL template reconstruction [`FULLSHIELD_EXPERIMENTAL_SQLCTX`]
Build:
1. At SQL sinks, render the 278 abstract string into a template with holes, then tokenize it with a SQL lexer that has dialect hints from the client package (pg, mysql2, sqlite, mssql).
2. Classify each tainted hole as one of:
   - value inside a quoted literal
   - numeric value position
   - identifier (table, column, `ORDER BY`)
   - keyword or operator position
   - whole-query control
3. Map to severity. A numeric position with digits-only `charClass` → no finding. A quoted-literal value whose `charClass` excludes the quote and backslash → no finding. Identifier position → finding with `sqlContext: "identifier"`, and the message says parameterization cannot fix it (an allowlist is required). Anything else → finding.
4. The finding gains `sqlContext` and a rendered template snippet with holes shown as `?{label}`.

Acceptance: fixtures cover each context, including `ORDER BY ${req.query.sort}` (identifier finding), `WHERE id = ${Number(x)}` (no finding), `LIKE '%${x}%'` (quoted-literal finding unless `charClass` is safe), and a multi-statement whole-query string. Gained and lost keys go to `DIFF.txt`. RASP SQL tokenizers (383) share the lexer, which the test asserts.

FP risk: the dialect may be unknown (generic `query` on an unrecognized client). In that case, fall back to today's behavior, never to "safe".

### Phase 280 — Shell command reconstruction [`FULLSHIELD_EXPERIMENTAL_SHELLCTX`]
Build: at `exec` / `execSync` / `spawn` with `shell: true` and the 27 shell sinks, render the template and tokenize it with POSIX shell rules (quotes, escapes, `$()`, backticks, redirections, `;`, `|`, `&&`). Classify each tainted hole:
- inside single quotes with no `'` possible in `charClass`
- inside double quotes (`$` and backtick still active)
- bare word
- option position (a leading `-` is possible, which is argument injection)

`execFile` / `spawn` without a shell get checked for argument injection only, when the hole is the first argument after the program and `charClass` allows a leading `-`.

Acceptance: fixtures for each context. `execFile('git', ['log', userRef])` with no `--` separator and `charClass` allowing `-` → `SAST-CMDI-001` with `shellContext: "option"` (an R10 change, `DIFF.txt`). The same with `'--'` before it → no finding.

### Phase 281 — URL abstract domain for SSRF [`FULLSHIELD_EXPERIMENTAL_URLCTX`]
Build: parse the 278 abstract string at SSRF sinks into scheme, authority, path, query and fragment, by where the literal prefix ends. Results:
- Tainted scheme or authority → finding as today.
- Taint only in the path after a literal `https://api.example.invalid/` → `ssrfContext: "path"`, severity lowered one step, still reported, because path traversal on internal APIs (`../admin`) is real.
- Taint only in the query or fragment → `ssrfContext: "query"`, severity low.
- `new URL(input, base)` and `url.resolve` are modeled: an absolute input overrides the base, so it counts as a tainted authority.

Acceptance: fixtures for each position, including the `new URL(req.query.u, base)` override case (finding with `authority`). Every severity change is listed in `DIFF.txt`.

### Phase 282 — HTML output context for XSS [`FULLSHIELD_EXPERIMENTAL_HTMLCTX`]
Build: at HTML sinks (`res.send` HTML, template raw outputs, DOM sinks from 101), parse the literal template around each hole with an HTML5 tokenizer state machine. Contexts:
- text node
- quoted attribute value
- unquoted attribute value
- URL attribute (`href`, `src`, `action`, `formaction`)
- event-handler attribute
- `<script>` body
- `<style>` body
- comment

Sanitizers clear only matching contexts (256 data):
- HTML escape clears text and quoted attributes, not URL attributes (`javascript:`), not script bodies.
- `encodeURIComponent` clears only the URL query component.
- `JSON.stringify` in a script body is not safe unless `<` is escaped.

Acceptance: a matrix test of 8 contexts × 6 sanitizers. `<a href="${escapeHtml(x)}">` gives a finding with `htmlContext: "url-attr"`. `<p>${escapeHtml(x)}</p>` gives none. `<script>var d = ${JSON.stringify(x)}</script>` gives a finding.

### Phase 283 — Path abstract domain [`FULLSHIELD_EXPERIMENTAL_PATHCTX`]
Build: at file-system sinks, render the path and track whether a tainted segment can contain `..`, `/`, `\`, `\0` or a leading `/`, using `charClass`. `path.join` / `resolve` / `normalize` are modeled, including that `path.join(base, '/etc/passwd')` keeps `base` but `path.resolve(base, '/etc/passwd')` drops it. `path.basename(x)` removes separators (it clears traversal but not a hidden-file read). A Windows mode applies when the project targets win32 (engines `os` or Electron).

Acceptance: fixtures cover `path.basename` (no traversal finding), `path.resolve` with an absolute input (finding), and the 258 `startsWith(base + sep)` guard (none). An `upload/${req.file.originalname}` fixture gives a finding unless `basename` is applied.

### Phase 284 — Static ReDoS analysis [`FULLSHIELD_EXPERIMENTAL_REDOS2`]
Upgrades `SAST-REDOS-001` (Phase 29), which only checks quantifier shapes.

Build:
1. Parse each regex literal (and `new RegExp` with a static pattern) into an NFA, supporting the JS regex syntax subset without backreferences. Backreferences and lookbehind → `unknown`, which is not a finding.
2. Detect exponential ambiguity (EDA: two distinct paths through one loop on the same string) and polynomial ambiguity (IDA) using the standard ambiguity checks on the NFA.
3. Report only when a tainted value reaches `.test` / `.match` / `.replace` / `.split` / `.exec` with that regex, and the 278 `charClass` permits the attack alphabet.
4. The finding includes the ambiguous sub-pattern and a generated attack-string shape (prefix, pump, suffix) built from the NFA. The regex is never executed.

Acceptance: fixtures `^(a+)+$` (exponential), `^\d*\d*$` (polynomial), and `^[a-z]+$` (none). A digits-only `charClass` on the input suppresses an attack that needs letters. Literal regexes never reached by taint are not reported (only under a separate audit flag). Old `SAST-REDOS-001` keys removed or added are listed in `DIFF.txt`.

FP risk: regexes with length guards before them (`if (s.length > 100) return`). 258 adds a length-guard shape; until then, the fixture documents a residual FP.

### Phase 285 — Control-flow type narrowing in plain JS [`FULLSHIELD_EXPERIMENTAL_NARROW`]
Phase 257 needs TypeScript. Plain JS projects get none of it.

Build: flow-sensitive refinement from runtime checks:
- `typeof x === 'number'`, `Number.isInteger(x)`, `Array.isArray(x)`, `x instanceof Date`, `x === true/false`, and `/^\d+$/.test(x)` in a dominating condition.
- `if (!checks) return/throw` patterns.
- `switch (x)` over literal cases.

Refinements update `charClass` and drop string-injection labels when the type is not a string. They merge at join points (intersection of refinements).

Acceptance: fixtures per check, plus a negative where the check is on another variable, and one where the refinement is lost after a reassignment. Results feed 279–283. Changes to findings go to `DIFF.txt`.

### Phase 286 — Taint through serialization round-trips [`FULLSHIELD_EXPERIMENTAL_ROUNDTRIP`]
Build: `JSON.stringify` → `JSON.parse`, `structuredClone`, `querystring` / `URLSearchParams` stringify-parse, `Buffer.from(x).toString()`, `atob(btoa(x))`, `encodeURIComponent` → `decodeURIComponent`, and `zlib` round trips in the same function all keep labels. Field paths keep labels where the structure is preserved (`JSON.parse(JSON.stringify(o)).a`). Today `JSON.parse` never clears taint (Section 6.2), and that stays. This phase adds field precision, not clearing.

Acceptance: a round-trip fixture keeps the finding, with field paths where the structure is known. A decode after a sanitize (`decodeURIComponent(encodeURIComponent(x))`) restores the dangerous labels, so the finding is kept.

### Phase 287 — Second-order sources from the database [`FULLSHIELD_EXPERIMENTAL_STORED`]
Values read from a database can hold attacker data written earlier.

Build: results of reads on model-pack data stores (`find*`, `query` result rows, `get` on Redis) become sources with the label set `stored` (a distinct origin). They are reported only when the value reaches a sink class where stored data is dangerous: SQL built by concatenation (second-order SQLi), HTML (stored XSS), shell, and template source. Severity is one step below direct request taint, confidence medium, `origin: "stored"` on the finding.

Acceptance: fixtures cover a username read from the DB concatenated into a second SQL query (finding, `origin: "stored"`), and the same value used only in a parameterized query (none). On by flag only. This is expected to add findings, so the realworld FP sample (76) is required before any promotion.

FP risk: high on apps that store only trusted data. That is why it stays a medium-confidence, separate origin, and why 288 links it to a real write path.

### Phase 288 — Stored XSS write→read linking [`FULLSHIELD_EXPERIMENTAL_STOREDLINK`]
Make 287 precise by requiring a matching untrusted write.

Build: from the route model (255), find routes where request input is written to a model field (`create` / `update` / `save` / `INSERT` with that column). From 287, find reads of that same model and field reaching an HTML sink. Link them into one path (85) with both routes. Only linked pairs get `confidence: high`. Unlinked 287 findings stay medium.

Acceptance: a fixture with a comment-post route writing `body` and a page route rendering `comment.body` raw gives a high-confidence finding with two routes. A field written only from a constant keeps its finding medium, not high. Field matching uses model names from packs (298, 299) or schema files. Unknown models are not linked.

### Phase 289 — Cross-request flow via session and cache [`FULLSHIELD_EXPERIMENTAL_XREQ`]
Build: writes of request input to `req.session.<k>`, `res.locals` persisted via session, signed cookies set by the server, and app-level caches (`cache.set(k, v)` from model packs, Redis via packs) become stored sources for reads of the same key in other routes. Key matching requires literal keys or a shared constant. Dynamic keys log a 271 event. Origin `session` or `cache`.

Acceptance: a fixture where `/set` stores `req.query.theme` in the session and `/page` renders it raw gives a finding with two routes. Different keys give none. A dynamic key gives an event only.

### Phase 290 — Environment and config sources [`FULLSHIELD_EXPERIMENTAL_ENVSRC`]
`process.env` is not request input, but it reaches sinks in ways that matter in multi-tenant and CI contexts.

Build: `process.env.*`, config files loaded via `dotenv` / `config` / `convict`, and `process.argv` (already a source) get origin `environment` with a separate severity table. They are reported only for the `cmdi`, `eval` and `ssti` sink classes, where operator-controlled values still create code execution in shared runners. `info` by default. With `scan.trustEnvironment: false` (config), they are raised to medium. Never a high finding.

Acceptance: `exec('deploy ' + process.env.BRANCH)` gives an info finding with `origin: "environment"`. `db.query('… ' + process.env.TABLE)` gives nothing (not in the listed classes). clean-app stays at 0 with the flag on, so no env-to-cmd pattern may exist there. Verify, don't assume.

### Lane I — Framework lowerings (291–310)

A framework phase is a compiler into the IR. It does not own a taint flag, a route list, or a sanitizer. It emits sources, sinks, calls, and route records that 251, 255, and 256 already understand. Version selection is phase 310. A phase that special-cases one library inside a SAST rule is sent back.

### Phase 291 — Express 5 semantics [`FULLSHIELD_EXPERIMENTAL_EXPRESS5`]
Express 5 is a separate lowering, chosen by the locked major, not a patch on the Express 4 model. A rejected promise or a throw inside an `async` handler is an IR edge to the error-handling middleware; Express 4 does not create that edge. Route strings compile with path-to-regexp v8: named wildcards (`/*splat`), optional `{...}` groups, and no inline regex. `req.query` is a getter. Its abstract value follows `app.set('query parser')`: `simple` is a flat string map, `extended` is nested objects and arrays (the operator-injection key set). A missing setting uses that major's documented default. An unknown parser value keeps every label and writes a 271 event.

Depends on: 251, 254, 255. Flag off: byte-identical.

Build:
1. Read the Express major from the lock row that the app's `require('express')` resolves to. Do not use the highest Express version in the tree.
2. Lower async rejection onto the error-middleware stack (307 fills the order; until 307, the edge targets the function with arity 4).
3. Compile v8 route strings into `Route.fullPath`. A v4-only inline regex in a v5 app is a 271 event, not a guessed path.
4. Lower `req.query` into CharClass plus a key set, `Finite` or nested `Unknown`.

Acceptance: the same routes in an Express 4 fixture and an Express 5 fixture. Only v5 has the rejection edge, the splat path, and nested query keys. v4 output matches today's route model. clean-app stays at 0.

FP risk: a monorepo with both majors. The lowering follows the `require` that built that app object. A wrong copy is a bug in the require edge, and the witness names the file that imported Express.

### Phase 292 — Fastify JSON-schema refinement [`FULLSHIELD_EXPERIMENTAL_FASTIFYSCHEMA`]
A Fastify `schema` is a transfer function on Effect, applied at the handler parameter, not a comment that the route is "validated." `type: integer|number|boolean` and a finite `enum` drop string-injection labels on that field only. A string `pattern` compiles into the same CharClass domain as 278; an unanchored pattern or a class that still admits a sink metacharacter drops nothing. `$ref` resolves inside the encapsulation scope (308) through `addSchema`. `coerceTypes: true` is an explicit cast in the IR, so the witness shows the coercion instead of a vanished taint bit. `removeAdditional` deletes unknown keys from the must-set and does not make the remaining keys safe.

Depends on: 251, 256, 278. Flag off: byte-identical.

Build:
1. Read `schema.body`, `querystring`, `params`, and `headers` from the route options object, including schemas shared through `$ref`.
2. Compile each field schema to a transfer function. Fail closed: a schema the compiler does not understand leaves the field tainted and writes a 271 event naming the keyword.
3. Record ajv options set in code (`coerceTypes`, `removeAdditional`). Options that are only in a comment do not count.

Acceptance: an integer `id` into SQL is not a finding; a sibling string field with no pattern still is. An unanchored `pattern` still is. A `$ref` to a shared integer schema behaves as if it were inline. A schema keyword outside the implemented set keeps the finding and emits one event.

FP risk: a schema that is replaced at runtime (`route.schema = …` from input). That assignment is not a static schema; the phase leaves the field tainted.

### Phase 293 — NestJS DI and pipes [`FULLSHIELD_EXPERIMENTAL_NESTDI`]
Nest providers are allocation sites. The injection token is the points-to key. Constructor parameters resolve to those sites, so `this.repo.query` is the repository method, not an unknown callee. `REQUEST`-scoped providers are context-sensitive: one abstract object per route (253's k=1), because a singleton would merge two requests' taint. Global, controller, and route `ValidationPipe` insert a transfer function on the edge into the handler argument. `whitelist` and `forbidNonWhitelisted` cut the key set down to decorated properties. class-validator decorators (`@IsInt`, `@IsUUID`, `@IsEnum`, `@Matches`) are the same transfer functions as 292, on fields, not on the whole object. A raw `@Body()` object with no pipe keeps `keys: Unknown`.

Depends on: 251, 253, 255, 272 when points-to is on; without 272, resolution is lexical and a failed lookup is a 271 event, not a guess.

Build:
1. Build the module graph from `@Module` providers, imports, and exports. A circular module iterates to a fixpoint with fuel; exhaustion marks the token `unknown`.
2. Attach pipes in Nest's documented order (global, then controller, then method).
3. Lower `@Body`, `@Query`, `@Param` to sources whose fields pass through the pipe transfer function before the method body.

Acceptance: a DTO field with `@IsInt()` reaching SQL is not a finding. The same handler forwarding raw `@Body()` to a repository string query is a finding. Two request-scoped providers do not share taint across routes (a fixture asserts the witness path stays on one route).

FP risk: a custom pipe whose class is not in source. It is an unknown transfer function, so it clears nothing.

### Phase 294 — Next.js App Router model [`FULLSHIELD_EXPERIMENTAL_NEXTAPP`]
The App Router is a pure function of the file tree, not a list of framework calls. A segment `(group)` adds no URL piece. An `@slot` is a parallel route. `[id]` and `[...slug]` are parameters and sources. A route group and an intercepting route `(.)` are distinguished by the parentheses grammar, not by a regex on the whole path. Exported `GET`/`POST`/`PUT`/`PATCH`/`DELETE` in `route.ts` are route records; the `Request` argument is origin `request`. Page and layout `params` and `searchParams` are sources, and the Promise form is an await edge (254): using them without `await` is a 271 event and still a source, because the Promise's resolved value is the tainted one. `headers()` and `cookies()` are sources. Server Components that read those sources and reach a sink are route records whose path is the folder function.

Depends on: 251, 254, 255. Flag off: byte-identical.

Build:
1. Implement the path grammar as a parser with an explicit rejection list (duplicate groups, a slot that is also a dynamic segment in an illegal position). A rejected file is a 271 event and is not given a made-up URL.
2. Lower handlers and server components into `Route` records, including the auth state already detected by phase 103's names, without copying phase 103's rules.
3. Model the Promise form as `await`. A `.then` on `params` uses 254.

Acceptance: one route handler, one page with `searchParams`, one `[...slug]` segment, and one `(group)` that does not appear in `fullPath`. The Promise form without `await` still reports, and the witness contains the event. A Pages Router file is not parsed by this grammar.

FP risk: a folder that happens to look like `app/` but is not the App Router root. The root is the `app` directory next to the Next config or the lockfile package that depends on `next`, not the first `app` folder in the repo.

### Phase 295 — Next.js server actions and form data [`FULLSHIELD_EXPERIMENTAL_NEXTACTION`]
A Server Action is a POST route whose body is not a function name. Arguments and `FormData.get` / `getAll` are origin `request`. The action is linked to the form or caller that references it, so the witness names the page. A string action id that is a literal ties the call. A computed id is a 271 event and the action stays a route with caller `unknown`, which does not drop the source. Auth is a dominating guard inside the action or on the route that renders the form, using the same auth names as phase 103. The action is `authState: absent` when neither exists. Inline actions and `'use server'` files both lower. The closure's bound values are effects, so a server action that forwards a client argument into SQL is an ordinary taint query after lowering.

Depends on: 251, 255, 294. Flag off: byte-identical.

Build:
1. Find `'use server'` modules and inline server actions. Treat exported async functions in those modules as actions.
2. Link callers by lexical reference and by a literal action id. Do not invent a link from a matching function name in another file.
3. Add a POST `Route` per action. `FormData` keys that are literals become field names; a dynamic key makes that read `keys: Unknown`.

Acceptance: an action writing form data into a string query with no auth guard is a finding whose witness includes the page. The same action with a dominating auth call is not an auth finding and is still an injection finding if the query is built by concatenation. A client component that never calls the action does not appear in the witness.

FP risk: a shared helper marked `'use server'` that is also called from a server component with a constant. The constant argument has no request origin, so the injection finding requires the request-labeled argument. The helper being a server action is not itself a finding.

### Phase 296 — GraphQL resolvers [`FULLSHIELD_EXPERIMENTAL_GRAPHQL`]
Each field resolver is a route record `GRAPHQL <Parent>.<field>`, not one route for the whole endpoint. Resolver `args` are origin `request`. `context` carries the auth predicate (311) and is not a general source. Parent object fields are origin `stored` when the parent was loaded from a data store (287), so a field resolver that concatenates `parent.name` into SQL is second-order, not a fresh request source. Apollo, Yoga, and type-graphql (`@Resolver`, `@Query`, `@Mutation`, `@FieldResolver`) lower into the same records. A query document that sits in the repo limits which fields are demanded; a document that arrives only at runtime does not, and every resolver stays live. Depth limits and complexity are phase 399, not this phase.

Depends on: 251, 255, 287. Flag off: byte-identical.

Build:
1. Lower resolver maps and decorator classes to one route record per field. The witness carries parent type and field name.
2. Args flow into the resolver body. Context flows only into the auth predicate unless the resolver reads an unsanitized context field and that field was assigned from a request source.
3. If an in-repo document selects a subset of fields, record the demand set. Missing documents do not clear unused resolvers.

Acceptance: a query resolver concatenating an arg into SQL is a finding. A mutation whose arg passed a finite enum schema (292-style, when that lowering is on) is not. A field that is not in an in-repo document is still analyzed. Two resolvers on the same parent do not share args.

FP risk: a resolver that loads its own id from `args` but the SQL uses a constant table. The finding follows the arg, not the fact that the file imports a database client.

### Phase 297 — tRPC procedures [`FULLSHIELD_EXPERIMENTAL_TRPC`]
A tRPC procedure is a route record whose path is the router path (`post.byId`). `.input(zod)` lowers to the same field transfer functions as 292: `z.number()`, `z.enum`, and `z.string().regex` with an anchor. `.input` that is a `z.any()` or a passthrough object clears nothing. Middleware order is the builder order. A procedure built from `protectedProcedure` (or any base created with `.use` of an auth middleware) inherits that auth predicate, including across `mergeRouters` in other files. A later `.use` does not retroactively protect procedures already created. Subscriptions are routes with origin `request` on the input and origin `stored` on payloads the procedure yields from a store.

Depends on: 251, 255, 292's transfer-function shape. Flag off: byte-identical.

Build:
1. Resolve router objects across files through the module IR, including `mergeRouters`.
2. Record the middleware prefix on the builder at each `.query` / `.mutation` / `.subscription` call.
3. Compile zod objects field by field. An unrecognized zod method is a 271 event and clears nothing.

Acceptance: a public procedure and a protected procedure reach the same sink. Only the public one has `authState: absent`. A `z.number()` id into SQL is not an injection finding. `z.string()` into SQL still is. A merged router keeps the prefix that created the procedure.

FP risk: an auth check written inside one procedure body and then copied by convention into others. Only the procedure whose IR shows the dominating guard is authenticated. The others stay absent, which is the point of the phase.

### Phase 298 — Prisma typed model [`FULLSHIELD_EXPERIMENTAL_PRISMA`]
`schema.prisma` lowers to a relation IR: models, fields, relations, and which fields are ids. Typed client calls (`findMany`, `create`, `update`, tagged `$queryRaw`) are not SQL-injection sinks. They are sinks for a different fact: a filter or `data` object whose key set is `Unknown` or intersects a privilege field (316). Tagged `$queryRaw` and `Prisma.sql` fragments are SQL templates in the 279 domain, with a hole at each interpolation. `$queryRawUnsafe`, `$executeRawUnsafe`, and `Prisma.raw` are raw SQL sinks. A whole request object passed to `where` is operator injection because its keys are `Unknown`. The model IR is what 288 and 316 read so they do not guess column names.

Depends on: 251, 278, 279. Flag off: byte-identical.

Build:
1. Parse `schema.prisma` with an in-tree parser. A file that fails to parse yields no model IR and a 271 event. Do not half-parse.
2. Lower typed calls and raw calls into different sink classes. The witness names which.
3. Compose `Prisma.sql` fragments in the string domain before classification.

Acceptance: a tagged template with a trusted literal is not a finding. An unsafe raw query of request input is. `where: req.body` is a finding even though the call is `findMany`. `where: { id: req.params.id }` with a string id is not operator injection (the key is finite) and is not SQL injection. A `data` object that can set `role` is phase 316's finding, not this one, when both flags are on; this phase still records the key set.

FP risk: a raw query whose only hole is a numeric CharClass inside a value position. 279 clears it. This phase must not report it a second time under a Prisma-specific id.

### Phase 299 — Sequelize, TypeORM, Mongoose, and Drizzle [`FULLSHIELD_EXPERIMENTAL_ORM2`]
The four libraries lower into one query-object domain: `{ keys: Finite|Unknown, values: Effect, operators: Set, rawFragments: StringDomain }`. Sequelize `query` and `literal`, TypeORM `query` and `createQueryBuilder().where(string)`, Mongoose `$where`, and Drizzle `sql.raw` are raw fragments and use 279 when the fragment is SQL. A filter object built from a request object is operator injection when keys are `Unknown`. `Model.create(req.body)` and the equivalent update keep the key set for 316. Packs are keyed by `appliesTo` ranges (310). A library version outside every range does not use a nearer major's semantics; it emits a 271 event and falls back to "raw string in, tainted string out," which never clears a label.

Depends on: 251, 279, 310. Flag off: byte-identical.

Build:
1. One lowering module per library, selected by the locked version.
2. Map the calls above into the shared domain. Do not copy their taint rules into the SAST files.
3. Ship one positive and one negative fixture per library: raw fragment, whole-object filter, and a literal query.

Acceptance: each library's raw API reports, each library's parameterized or tagged form does not, and a whole-object `where` reports once. An unsupported major reports the raw-string fallback and the event, and does not report a typed-query false positive from the previous major's rules.

FP risk: a query builder whose `.where('id = ?', id)` binds the value. The hole is a value position. Reporting it is a bug in the lowering, and the negative fixture is that call.

### Phase 300 — Socket.io and ws handlers [`FULLSHIELD_EXPERIMENTAL_WS`]
A socket handler is a route `WS <event>` only when the event name is a finite set of literals. `onAny`, a computed event name, or `socket.on(req.params.e, …)` makes the payload a source and writes a 271 event, and it does not invent one route per possible string. The payload is origin `request`. Connection auth is the middleware that dominates the connection object before the first listener (`io.use`, `verifyClient`, an upgrade check). A check inside one event handler does not authenticate the other events. `ws` `message` is a single route `WS message` because the protocol has one data event; the bytes are a source, and `JSON.parse` keeps field paths (286).

Depends on: 251, 254, 255. Flag off: byte-identical.

Build:
1. Collect literal `socket.on` names and the `ws` message handler.
2. Attach the connection-level auth predicate to every event on that server object. A different `io` instance does not inherit it.
3. Lower the payload argument to a source. Binary frames stay tainted strings; the phase does not decode application protocols.

Acceptance: an event payload reaching SQL is a finding. A second event on the same server without its own check inherits connection auth if `io.use` ran, and does not inherit auth from the sibling handler. A computed event name produces one source plus one event, not a finding titled with a guessed name.

FP risk: a broadcast of a server-generated literal on the same connection. The literal has no request origin. Only the client payload does.

### Phase 301 — Serverless handlers [`FULLSHIELD_EXPERIMENTAL_SERVERLESS`]
The trigger is part of the type of the event. AWS Lambda `event.body`, `queryStringParameters`, `pathParameters`, and `headers` are origin `request` when the manifest (SAM, serverless.yml, function URL) says the trigger is HTTP. An S3 or cron trigger on the same handler shape is origin `event`, one severity step lower, because the caller is not an HTTP client of this app. Vercel and Netlify `(req, res)` and Web `Request` handlers are HTTP. Cloudflare Workers `fetch(request, env)` is HTTP; `env` bindings are origin `environment` and follow 290's class limits. The path comes from the manifest. A handler with no manifest is origin `event` and the witness says the trigger is unknown, which does not upgrade it to HTTP.

Depends on: 251, 255, 290. Flag off: byte-identical.

Build:
1. Parse the manifest formats with in-tree parsers. A parse failure is a 271 event and the HTTP upgrade does not happen.
2. Lower only the fields the trigger type documents. Do not treat the whole `event` object as a request body.
3. One fixture per platform, plus one Lambda that is cron-triggered and must not be origin `request`.

Acceptance: an HTTP Lambda body reaching `exec` is a request finding. The cron fixture reaching `exec` is origin `event` at the lower severity. A Worker `env.API_HOST` used as a fetch URL is environment-origin and follows 281, not this phase's HTTP source.

FP risk: a monorepo manifest that names a function the file does not export. No route record is created for a name that does not resolve.

### Phase 302 — Queue consumers [`FULLSHIELD_EXPERIMENTAL_QUEUE`]
A consumer payload is origin `queue`: BullMQ `job.data`, kafkajs `message.value`, amqplib `msg.content`, SQS `Body`. Severity is one step below the same sink fed by `request`, and the witness carries the queue name when it is a literal. `JSON.parse` of the body keeps field paths (286). When a producer in the same repo enqueues a request-labeled value on that same literal queue name, the consumer's origin becomes the pair `request → queue`, confidence high, using the same link shape as 288. A dynamic queue name does not link. A producer that enqueues a constant does not promote the origin. The phase does not connect to a broker.

Depends on: 251, 286, 288's link shape. Flag off: byte-identical.

Build:
1. Lower the four consumer APIs to sources.
2. Find `add` / `send` / `publish` calls and link them only on literal queue names and literal routing keys.
3. Decode step: a `JSON.parse` of the payload is a field-preserving cast, not a sanitizer.

Acceptance: a consumer reaching `exec` is a finding with origin `queue`. The same payload reaching a parameterized query is not an injection finding. An in-repo producer of `req.body` on queue `jobs` promotes the matching consumer. A different queue name does not.

FP risk: two queues that share a helper named `enqueue`. The link uses the queue-name argument, not the helper name.

### Phase 303 — Remix, SvelteKit, and Nuxt loaders [`FULLSHIELD_EXPERIMENTAL_METAFRAME`]
Each framework has a file-system route grammar, version-keyed by 310, compiled by a real parser the way 294 parses the App Router. Remix `loader` and `action` see `request`, `params`, and form data. SvelteKit `load`, form actions, and `+server` see `url`, `params`, and `request`. Nuxt `defineEventHandler` sees `getQuery`, `readBody`, and `getRouterParam`. `event.locals` and Remix `context` are request-scoped heap cells (289's shape, lifetime one request, not the session). A write of request input to `locals` is visible to later middleware and loaders on that request only. A layout loader's data is an argument effect into the page, not a global.

Depends on: 251, 255, 310. Flag off: byte-identical.

Build:
1. One grammar per framework. A file that matches two grammars is a 271 event and is not given two routes.
2. Lower the documented source APIs. A framework helper that is not in the lowering stays an ordinary call.
3. Thread `locals` as a heap cell with request lifetime.

Acceptance: one fixture per framework shows the route path and a source reaching a sink. A `locals` write on the request is visible later on that request and not on a sibling request fixture. A version outside the grammar's range emits an event and does not reuse the previous major's path rules.

FP risk: a `+server.ts` that is not under `src/routes` or `app/routes` as the config names the routes directory. The config value wins. A guessed directory is a bug.

### Phase 304 — Electron IPC handlers [`FULLSHIELD_EXPERIMENTAL_ELECTRONIPC`]
An IPC channel is a route `IPC <channel>` when the channel name is a literal. Arguments of `ipcMain.handle` and `ipcMain.on` are origin `renderer`, which is request-equivalent for sink purposes and is named separately so a finding does not say "HTTP." The preload `contextBridge.exposeInMainWorld` is the export map: the witness says whether the channel is exposed and to which API object. A channel that is not on the bridge is still a source when phase 102 says `nodeIntegration` is on or `sandbox` is off, because the renderer can require `electron` directly. When the bridge is the only exposure and the channel is absent from it, the route exists but the finding's confidence drops to low and the witness says "no bridge entry." Sinks are the main-process file, shell, and `child_process` calls. The renderer process is not scanned with Node sink rules except through this boundary.

Depends on: 102, 251, 255. Flag off: byte-identical.

Build:
1. Collect literal channels and handle signatures, including the argument index.
2. Parse the preload's `contextBridge` object literal. A computed expose is a 271 event.
3. Combine with phase 102's integration facts. Do not re-detect `webPreferences` here.

Acceptance: a channel writing a renderer-supplied path is a finding. The same channel that runs the path through `path.basename` and the 283 guard is not a traversal finding. A channel missing from the bridge while sandbox is on is low confidence. A channel missing from the bridge while `nodeIntegration` is on stays high.

FP risk: a main-process handler invoked by `ipcMain.emit` from the main process itself with a constant. The constant is not origin `renderer`. The witness's origin field is the check.

### Phase 305 — CLI argument sources [`FULLSHIELD_EXPERIMENTAL_CLI`]
Commander and yargs values are origin `cli`. They are reported only at `cmdi`, `path`, and `eval` sinks, at low severity, because the operator already has a shell. A package is a CLI when its `package.json` has `bin` or its entry file builds a commander/yargs parser. A library that mentions `process.argv` in a test file is not a CLI. `execFile` with an array is argument injection only when 280 says the hole can be an option. A subcommand callback's positional args are sources. Default values that are literals are not.

Depends on: 251, 280. Flag off: byte-identical.

Build:
1. Detect the CLI entry. Do not mark every package that depends on `yargs`.
2. Lower option and positional values to origin `cli`.
3. Restrict the sink classes. An SQL sink fed only by `cli` emits nothing in this phase.

Acceptance: a flag passed to `exec` is a low finding. The same value passed as an `execFile` array element after `--` is not. A library fixture with no `bin` and no parser construction emits nothing. clean-app stays at 0.

FP risk: a CLI that shells out to a fixed command and appends a user path as a quoted argument. 280 decides. This phase must not report a second id when 280 already classified the hole as safely quoted.

### Phase 306 — Template engines [`FULLSHIELD_EXPERIMENTAL_TEMPLATES`]
EJS, Pug, Nunjucks, Handlebars, and Marko lower to functions whose output is an HTML context stack (282), not a string. Each construct has a documented output kind: escaped text, raw HTML, attribute, or script. Handlebars `SafeString` and Nunjucks `| safe` push `raw`. A helper's return value uses the helper's effect. Partials and includes are calls: the argument object flows into the partial's parameters, and the partial's output context is the context at the include site, not "HTML" in general. A raw include inside a `<script>` stays a script-body context. The template file is parsed by that engine's grammar subset. A construct outside the subset is a 271 event and is treated as raw, which is the sound direction.

Depends on: 251, 282. Flag off: byte-identical.

Build:
1. One grammar subset per engine, with an explicit raw-output list.
2. Lower includes as calls through the module resolver (template path aliases included).
3. Hand the output stack to 282. Do not keep a second XSS rule here.

Acceptance: one raw and one escaped fixture per engine. An escaped interpolation in a text node is not a finding. The same helper returning `SafeString` is. A partial that receives `req.query.q` and prints it raw is a finding whose witness includes both files. An unknown tag is an event and is raw.

FP risk: a helper that HTML-escapes and also returns `SafeString`, which double-encodes. The lowering trusts `SafeString` as raw because that is what the engine does. The negative fixture is an escaped construct that does not use `SafeString`.

### Phase 307 — Express middleware order [`FULLSHIELD_EXPERIMENTAL_MWORDER`]
Registration order is a sequence of IR statements. A middleware covers a route only when three things hold: it was registered earlier, its path pattern matches the route (the same compiler as 291), and the passing branch calls `next` or otherwise continues. A middleware registered after the route does not cover it, even if the source reads top to bottom in another file that was imported earlier. Error handlers (arity 4, or Express 5 rejection edges) are a separate stack and do not count as auth. Router mounts prefix the pattern. `app.use` on `/` is not a wildcard for a router that was mounted on its own app unless the mount is in the sequence.

Depends on: 251, 255, 291 for v5 patterns. Flag off: byte-identical.

Build:
1. Record each `use`, `route`, and mount as an ordered statement, across files, in evaluation order of the module IR.
2. Match patterns with the version's route compiler.
3. A middleware that does not call `next` on the success path covers nothing past it (it ends the chain).

Acceptance: the same auth middleware before a route, after a route, and on a sibling path. Only the first covers the route. An error handler registered before the route does not cover it. The witness lists the statement index.

FP risk: auth inside a factory invoked at the wrong time. Evaluation order follows the IR, not the textual order of function declarations. A factory called after the route is the "after" case, and the fixture says so.

### Phase 308 — Fastify plugin encapsulation [`FULLSHIELD_EXPERIMENTAL_FASTIFYSCOPE`]
Fastify's encapsulation is a lexical scope tree on the IR. A hook or decorator registered inside `register` applies to routes in that subtree only. `fastify-plugin` is an explicit scope break: the hook applies to the parent. A child plugin does not protect a sibling plugin. Decorators shadow. `onRequest` and `preHandler` are ordered inside the scope. A hook added in a parent after the child was registered still wraps the child, matching Fastify's documented encapsulation, and the witness records parent versus child so a reader can see why.

Depends on: 251, 255. Flag off: byte-identical.

Build:
1. Build the `register` tree. A dynamic plugin function that is not a local function is a 271 event and is treated as a scope break (sound: it might use `fastify-plugin`).
2. Attach hooks to routes in the subtree.
3. Resolve `$ref` schemas (292) in the same tree.

Acceptance: an auth hook in a child plugin does not cover a sibling's route. The same hook wrapped in `fastify-plugin` does cover the sibling. A decorator override in the child does not change the parent route's witness.

FP risk: a plugin that calls `fastify-plugin` under a computed condition. The condition is not evaluated (R15). The plugin is a scope break plus a 271 event.

### Phase 309 — Koa and Hono [`FULLSHIELD_EXPERIMENTAL_KOAHONO`]
Koa middleware is an onion: each `app.use` receives the downstream chain as its continuation. A middleware covers a route only if the route is downstream of it and the middleware awaits `next` on the passing branch. `ctx.request.body`, `ctx.query`, and `ctx.params` are sources. Hono is a sequence, like 307, and `c.req.query()`, `param()`, `json()`, and `parseBody()` are sources. Validators in a Hono chain are transfer functions when they match the 292 shape; a validator the compiler does not know clears nothing. Both frameworks emit the same `Route` record as Express. They do not get a private finding id for "uses Koa."

Depends on: 251, 255, 307's cover rule. Flag off: byte-identical.

Build:
1. Lower Koa as a continuation chain and Hono as a statement sequence.
2. Sources are the APIs above. A custom `ctx.body` parser is a source only when its argument is the raw request body.
3. Feed both into the route model.

Acceptance: one fixture per framework with a source reaching a sink, and one Koa middleware that does not await `next` and therefore does not cover the downstream route. A Hono validator of type number removes string-injection labels; a missing validator does not.

FP risk: Koa middleware that assigns `ctx.state.user` after `await next()`. That assignment is not a dominating guard for the downstream route. The fixture is the auth check on the wrong side of `next`.

### Phase 310 — Version-keyed framework semantics [`FULLSHIELD_EXPERIMENTAL_VERKEY`]
Every framework and library lowering carries `appliesTo`, a node-semver range, on the model row. The selected row is the one whose range contains the locked version of the package the `require` resolves to. No lockfile entry: use the newest row and set `version-assumed` on the witness. Two rows matching one version is a test failure, not a runtime pick. A version in a gap between rows uses the raw fallback from 299 and a 271 event. This phase is the selector. It does not contain Express rules of its own. Later lowerings call it and do not read `node_modules/*/package.json` version fields ad hoc.

Depends on: 261's lock view when present; the lockfile parser otherwise. Flag off: byte-identical.

Build:
1. Add `appliesTo` to the model schema and reject rows without it.
2. Implement the selector. Cache the choice per resolved package path.
3. Fixtures: Express 4 and 5, Next 14 and 15, each forced to the matching row. A lockfile with the version deleted yields `version-assumed` and still analyzes.

Acceptance: the selector test feeds two versions and asserts two different row ids. A gap version asserts the event and the fallback. A model row without `appliesTo` fails the schema test. Default scan with the flag off does not read the field.

FP risk: a package whose lockfile version is a git dep without a semver (phase 120). The selector emits `version-assumed` and does not pretend the tag is a version.

### Lane J — Auth predicates and access edges (311–330)

Authentication and authorization are predicates on route records. A finding is a missing edge when a later rule requires that edge. Section 4.3 still holds: these phases report an IR edge and a stated confidence. They do not claim a deterministic proof that an attacker can read an object.

### Phase 311 — Authentication mechanism model [`FULLSHIELD_EXPERIMENTAL_AUTHMECH`]
Each route gets an auth predicate from a lattice: `none`, `session`, `jwt`, `apikey`, `passport:<strategy>`, `framework:<name>`, or `unknown`. The predicate is the middleware or guard that dominates the handler in 307, 308, or 309 order, not a name that merely appears in the file. Options are part of the predicate: passport `session: false`, a JWT `algorithms` list, an API key read from a header rather than a query (326). A route is authenticated only when every path that reaches the handler has a known mechanism. One path of `none` means not uniform, and the witness lists that path. `unknown` is a call that looks like auth but is not in the catalog or the config. It is not `none` and it is not authenticated. This phase emits no finding.

Depends on: 255, 307, 308, 309. Flag off: byte-identical.

Build:
1. Join the lattice as specified. Do not collapse `unknown` into `none`.
2. Read project function names from config as `framework:custom` plus the name.
3. Store the predicate on the route record.

Acceptance: fixtures for passport, JWT middleware, session, API key, NextAuth, a Nest guard, and a Fastify auth plugin. Middleware registered after the route leaves `none`. A function named `authenticate` that is not in the catalog is `unknown`, and a test asserts it is not stored as `session`.

FP risk: a function named `login` that only renders a form. It is not a mechanism. The negative fixture is that function.

### Phase 312 — Authorization check recognition [`FULLSHIELD_EXPERIMENTAL_AUTHZ`]
Authorization is a second predicate: `none`, `role`, `permission`, `policy`, `ownership`, or `unknown`. A check counts only when it dominates the sink, using the same return-or-throw shape as 258. Catalog entries are `hasRole`, `can`, `authorize`, CASL, and casbin, plus config names. A computed permission string is `unknown` and does not satisfy a later rule that requires `role`. A check after the sink does not count. This phase emits no finding.

Depends on: 251, 311. Flag off: byte-identical.

Build:
1. Mark catalog calls with their lattice kind.
2. Require dominance on the IR before the sink.
3. Attach the predicate to the sink instruction and the route.

Acceptance: the same check before the sink sets the predicate; after the sink it does not. A config-named function works. An unlisted `can` helper stays `none`.

FP risk: a helper named `can` that parses input. Without a catalog or config entry it stays `none`. The schema requires `kind` to be a lattice member, so a row cannot be added as a vague match.

### Phase 313 — Route, auth, and data-access matrix [`FULLSHIELD_EXPERIMENTAL_ACLMATRIX`]
The matrix is a pure function of route records. One row is method, path, auth predicate, authz predicate, owner-scope, and sink classes. Rows sort by method, path, then file. `explain --matrix` prints them. With the flag on, `scan --json` gains an experimental `matrix` array and the finding list is unchanged. No row is a finding. `unknown` is not printed as `none`.

Depends on: 311, 312. Owner-scope is `not-computed` until 314 is on. Flag off: byte-identical, and the JSON has no `matrix` key.

Build:
1. Implement the pure function.
2. Snapshot a fixture with public, authenticated, and admin routes.
3. Fail the test if a matrix row contains a finding-rule message string.

Acceptance: three routes produce three rows with the matching predicates. Flag off, findings are unchanged. An `unknown` auth cell stays `unknown`.

FP risk: a consumer treating `unknown` as safe. The schema description says it is not safe, and 315 is not allowed to skip on `unknown` by calling it safe.

### Phase 314 — Ownership data flow [`FULLSHIELD_EXPERIMENTAL_OWNERFLOW`]
The principal is origin `principal`: `req.user.id`, the session user id, `ctx.state.user`, and the user object the auth lowering names. It is not a general XSS source. A data access is `owner-scoped` only when a must-alias of that value reaches a filter key the model IR marks as the owner field. A may-alias is `unknown`, not scoped. With no model IR, the cell is `unknown`. `not-scoped` is only a query the model understands, whose finite filter keys omit the owner field, while the lookup key is origin `request`.

Depends on: 251. Must-alias uses 272 when it is on; otherwise only a same-variable syntactic flow is must, and every other flow is `unknown`. Flag off: byte-identical.

Build:
1. Mark principal reads.
2. Track them into filter keys.
3. Compare with the model's owner field name, not a hard-coded `userId`.

Acceptance: a query filtered by the principal is `owner-scoped`. The same model filtered only by `req.params.id` with a finite key set is `not-scoped`. An unresolved alias is `unknown`. A test asserts `unknown` is not stored as `not-scoped`.

FP risk: any numeric id being treated as the principal. The phase follows the principal origin, not the number type. The negative fixture filters only by `req.params.id`.

### Phase 315 — IDOR from the ownership edge [`FULLSHIELD_EXPERIMENTAL_IDOR2`]
Emit `SAST-IDOR-002` (medium) only when the auth predicate is a known mechanism, the authz predicate is not `role` or `policy`, the access is `not-scoped`, and the lookup key is origin `request`. `unknown` scope emits nothing. An unauthenticated route emits nothing from this id. The message cites the route, the id source, and the missing owner edge. It does not say the object is exposed. Confidence stays medium. Phase 107's id is unchanged. This is an edge report, not the deterministic authorization proof Section 4.3 refuses.

Depends on: 312, 314. Flag off: byte-identical.

Build:
1. Read the predicates. Do not re-detect auth.
2. Emit one finding per access instruction.
3. Skip `unknown`, admin-shaped checks, and unauthenticated routes.

Acceptance: a scoped update emits nothing. An authenticated unscoped update by `req.params.id` emits one medium finding. An admin route with the same query emits nothing. An unauthenticated route emits nothing from this id.

FP risk: a raw SQL `EXISTS` owner check the model IR does not see. That access stays `unknown` because 314 will not mark a raw query `not-scoped` without a model. The forbidden outcome is a finding from `unknown`.

### Phase 316 — Role-field mass assignment [`FULLSHIELD_EXPERIMENTAL_MASSASSIGN`]
Privilege fields are schema fields tagged `privilege`, plus the config list (`role`, `isAdmin`, `permissions`, `tenantId`, and user-added names). Emit `SAST-MASSASSIGN-001` (high) when a create or update `data` object has `keys: Unknown`, or a finite key set intersecting that privilege set, and no dominating allowlist removes those keys. A DTO transfer function that dropped the field is safe. Spread of `req.body` is `keys: Unknown`. A finite set names the fields in the witness. An unknown key set says "unknown keys" and does not invent property names.

Depends on: 298 or 299, or the config list alone for the default names. Flag off: byte-identical.

Build:
1. Build the privilege set from tags and config.
2. Read the key set at create and update sinks.
3. Treat `pick`, a DTO, and `removeAdditional` as transfer functions that run first.

Acceptance: whole-body update and object spread report. A pick that drops `role` does not. A pick that keeps `role` does. A body that only sets `title` on a tagged model does not.

FP risk: a non-user model with a field literally named `role`. Tags win. The default name list applies only when the model has no tags, and the message says the match was by name.

### Phase 317 — JWT verification edges [`FULLSHIELD_EXPERIMENTAL_JWTDEEP`]
Verification options are an abstract record. Algorithm confusion is `algorithms` containing both an HMAC name and an asymmetric name, or `algorithms` missing while the key is a PEM public key or a certificate. An explicit `none` algorithm is critical. `kid` flowing into a path or SQL is a normal taint query with origin `jwt-header`. `jku` or `x5u` reaching `fetch` is SSRF with that origin. Missing `audience` or `issuer` is a finding only when the model row says the issuer is third-party. A locally issued HMAC session token with an explicit algorithm does not need an issuer finding. The phase does not verify a token and does not fetch JWKS (R15).

Depends on: 251, 281. Flag off: byte-identical.

Build:
1. Abstract the options object. An unknown spread element in `algorithms` counts as dangerous.
2. Classify key material by PEM headers or by a `readFileSync` of the public half. Unknown key type plus missing `algorithms` reports.
3. Reuse path, SQL, and SSRF queries for `kid` and `jku`. Do not add a second SQL rule.

Acceptance: HMAC plus RSA in one list reports. A single `RS256` with a public PEM does not. `kid` concatenated into a filename is a path finding with origin `jwt-header`. A `jku` fetch is SSRF. A local HMAC verify with an explicit algorithm and no `audience` does not report an issuer finding.

FP risk: sign and verify in one function with two keys. Only the verify call's key argument is judged. The fixture contains both calls.

### Phase 318 — OAuth and OIDC client flow [`FULLSHIELD_EXPERIMENTAL_OAUTH`]
Extract a two-step machine from the IR: the authorize redirect and the callback. `state` counts only when the start writes a nonce onto the session or a cookie and the callback's dominating branch compares the returned state to it. Generating `state` and never reading it reports. PKCE is required when the client is public (no client secret in the lowering, or a SPA, mobile, or CLI flag). A confidential client with a secret does not get the PKCE finding. `redirect_uri` taken from the request carries the redirect label. OIDC `nonce` must be compared on the callback before the id token is accepted. Rule id `SAST-OAUTH-001`; the witness names the missing edge. The phase does not perform a login.

Depends on: 251, 255, 289. Flag off: byte-identical.

Build:
1. Recognize passport OAuth strategies and `openid-client` as the machine. Other libraries are model rows.
2. Check state compare, PKCE for public clients, redirect_uri provenance, and nonce compare.
3. Emit one finding per missing edge so the witnesses do not merge into "OAuth is wrong."

Acceptance: each missing edge has a fixture that reports that edge and not the others. A complete flow reports nothing. A confidential client without PKCE reports nothing for PKCE. `redirect_uri: req.query.next` reports. A literal redirect URI does not.

FP risk: a state compare inside a helper. It counts when the call dominates the token exchange. A helper that is never called does not.

### Phase 319 — Session configuration [`FULLSHIELD_EXPERIMENTAL_SESSIONCFG`]
Cookie and session options are an abstract record: `httpOnly`, `secure`, `sameSite`, `signed`, secret source, `saveUninitialized`, `resave`. Missing `httpOnly` or `sameSite` on a session cookie reports. Missing `secure` is low when no dominating literal sets the environment to development, and is not dropped. A literal secret shorter than 32 characters reports even if 333 is off. A literal secret also takes origin `secret` for 331. `saveUninitialized: true` is info. The existence of a session is not a finding.

Depends on: 251. Flag off: byte-identical.

Build:
1. Abstract `express-session`, `cookie-session`, and `res.cookie`, including a function that returns a literal object.
2. Apply that table.
3. Exclude cookie names `csrf` and `_csrf` from the `httpOnly: false` check. Other exceptions come from config.

Acceptance: `httpOnly`, `sameSite: 'lax'`, and a long `process.env` secret emit nothing. Omitting `httpOnly` reports. A 4-character secret reports. `saveUninitialized: true` is info.

FP risk: a non-session cookie that script must read. Only the default csrf names and config entries are excluded. A cookie named `token` is not assumed to be a CSRF token.

### Phase 320 — Password storage and reset tokens [`FULLSHIELD_EXPERIMENTAL_PASSWORD`]
A field tagged `password` must pass through a catalog hash (`bcrypt`, `scrypt`, `argon2`) before the store. Direct assignment is the missing-hash finding. `sha1` or `md5` is a different finding, weak hash, not missing hash. A reset token must come from `crypto.randomBytes` of length at least 32. `randomUUID` is medium because the space is smaller. The stored reset token must be hashed, and the compare must be `timingSafeEqual` or a catalog compare. A reset token in a query string is its own finding. The user's password length is not judged.

Depends on: 251 and a field tag or config list. Flag off: byte-identical.

Build:
1. Tag password and reset-token fields.
2. Require the catalog hash on the store path and a constant-time compare on the check path.
3. Flag query-string placement separately.

Acceptance: `bcrypt.hash` before save emits nothing. Direct assignment reports the missing-hash id. `sha1` reports the weak-hash id and not the missing-hash id. A 16-byte token reports. `===` reports. `timingSafeEqual` does not. `?token=` reports.

FP risk: an importer that writes already-hashed passwords. Config on that function skips the missing-hash finding and still reports a visible weak algorithm. The witness names the config skip.

### Phase 321 — Brute-force protection on sensitive routes [`FULLSHIELD_EXPERIMENTAL_BRUTE`]
Sensitive routes are login, reset, and MFA, from the auth lowering plus config paths. A path is not sensitive because it contains the substring `auth`. Coverage requires a rate-limit middleware that dominates the route in 307 order, whose key includes the principal, the username field, or the client address. A limiter registered later does not count. A constant key does not count, and the witness says the bucket is shared. Emit `CONFIG-BRUTE-001` (medium). This phase does not block requests.

Depends on: 307, 311. Flag off: byte-identical.

Build:
1. Mark the sensitive set.
2. Abstract the dominating limiter's key.
3. Emit when the limiter is missing or the key is constant.

Acceptance: a login route limited by username emits nothing. The same limiter registered after the route reports. Key `'all'` reports. A health route does not.

FP risk: a limiter inside the handler. It counts when it dominates the credential check. A limiter on a non-dominating branch still reports.

### Phase 322 — CSRF and cookie-authenticated mutations [`FULLSHIELD_EXPERIMENTAL_CSRF2`]
A `POST`, `PUT`, `PATCH`, or `DELETE` (plus methods added in config) whose auth predicate is cookie-backed needs a dominating CSRF check. Bearer and header API-key auth do not. The check is catalog middleware or a dominating compare of a request token to a session token. A custom header counts when its name is a literal and the check dominates. GET is not reported. `SameSite=Lax` is recorded in the witness and is not a substitute. Emit `CONFIG-CSRF-001` (high).

Depends on: 307, 311, 319. Flag off: byte-identical.

Build:
1. Select routes by method and cookie-backed auth.
2. Recognize catalog middleware and explicit compares.
3. Keep `SameSite` in the witness without clearing the finding.

Acceptance: cookie session, POST, no check, reports. Dominating CSRF middleware does not report. Bearer-only does not. GET does not. `SameSite=Lax` alone still reports.

FP risk: a JSON API that checks a custom header the catalog does not know. Config adds the name. Until then the finding's message says the check was not in the catalog.

### Phase 323 — CORS origin abstract value [`FULLSHIELD_EXPERIMENTAL_CORSV2`]
The origin option lowers to literal, reflect-request, regex, function, or `null`. Reflect plus `credentials: true` is critical. An allowed `null` origin is high. A regex is searched, under fuel, for one concrete string the regex accepts that is not a boundary match of the intended host (`notevil.com` versus `evil.com`, or a missing anchor). That string goes in the witness. It is not found by contacting a network. A backreference the automaton cannot represent is `unknown` and low, never "safe." A function that is not the identity echo is low. The phase does not send a preflight.

Depends on: 278. Flag off: byte-identical.

Build:
1. Abstract the option, including arrays of literals.
2. Search the bounded automaton. Exhaustion is a 271 event and a low finding.
3. Pair the result with `credentials`.

Acceptance: a literal origin emits nothing. Reflect with credentials is critical. The suffix regex's witness contains the counterexample string. An anchored single-host regex emits nothing. `origin: 'null'` reports.

FP risk: a regex intended to allow two hosts that the automaton flags. The witness shows the string. If that string is a host the user wanted, they add it as a literal. The phase does not maintain a second allowlist inside the regex.

### Phase 324 — Account enumeration branches [`FULLSHIELD_EXPERIMENTAL_ENUM`]
On login and reset handlers, the unknown-user arm and the known-user arm must not differ in status code or in returned literal message. The comparison is the IR's return arguments. Timing is not measured and is not claimed. A difference that is only a log line is info. Echoing `user.email` is not given this id. Emit `SAST-ENUM-001` (low) with the two literals in the witness.

Depends on: 251 and the sensitive-route set from 321. Flag off: byte-identical.

Build:
1. Find the branch on the user-lookup result, not the branch on password correctness.
2. Compare status and literal payload.
3. Leave the password-wrong arm out.

Acceptance: 404 versus 200 on reset reports. The same 200 and the same literal do not. A log-only difference is info. A fixture that returns `user.email` does not get this id.

FP risk: the ordinary wrong-password branch. It is excluded by the arm definition, and the fixture includes it so a regression that flags it fails.

### Phase 325 — Multi-tenant isolation edge [`FULLSHIELD_EXPERIMENTAL_TENANT`]
Tenant id is origin `tenant`, from the auth predicate or config (`req.tenant.id`). On a model tagged `tenantOwned`, reuse 314's must-flow against the tenant field. Emit `SAST-TENANT-001` (high) when the scope is `not-scoped` and the route is authenticated. `unknown` emits nothing. One literal relation hop is walked; if that relation is not tenant-owned, a second finding says the edge stopped there. A dynamic include is a 271 event and `unknown`. The message does not say another tenant's row was returned.

Depends on: 314, 298 or 299. Flag off: byte-identical.

Build:
1. Mark tenant reads.
2. Reuse the owner-flow query with the tenant field.
3. Walk one literal relation. Config `tenantBypass` on a function skips it and the witness records the bypass.

Acceptance: a tenant-filtered query emits nothing. The same model loaded only by `req.params.id` reports. A nested untagged include reports the stopped edge. An unresolved alias emits nothing.

FP risk: a maintenance job that intentionally scans every tenant. It needs `tenantBypass`. The default is no bypass, so the job reports until the config names it.

### Phase 326 — API keys in query strings [`FULLSHIELD_EXPERIMENTAL_APIKEYQUERY`]
A read of an API key from `req.query`, a URL search param, or a Web `request.url` query is `SAST-APIKEY-QUERY-001` (medium): the value then sits in access logs and `Referer`. The same read from a header emits nothing. Identity comes from the 311 predicate or from config names, not from the substring `key` on every parameter. A default-name match that never reaches a compare is low, and the message says the match was by name.

Depends on: 255, 311. Flag off: byte-identical.

Build:
1. Find query reads that flow into an API-key compare, plus the default name list.
2. Exclude header reads.
3. Leave cloud signed-URL parameter names off the default list. Config adds them.

Acceptance: `req.query.apiKey` used as auth reports medium. `Authorization` does not. A parameter `q` does not. A name-only match is low.

FP risk: a single-use signed URL. Config marks that parameter `signedUrl`. The default list does not contain vendor signature names.

### Phase 327 — GraphQL field authorization [`FULLSHIELD_EXPERIMENTAL_GQLAUTHZ`]
Each field route from 296 needs an authz predicate or a catalog schema directive such as `@auth`. Emit `SAST-GQL-AUTHZ-001` (medium) when the parent is public, the field has neither, and the resolver reaches a data-store sink or returns a field tagged sensitive. A resolver that returns only a literal is not a finding. Introspection is not a finding here. An unknown directive still reports, and the witness quotes the directive name so it can become a model row.

Depends on: 296, 312. Flag off: byte-identical.

Build:
1. Join field routes to predicates and directives.
2. Restrict to store sinks and tagged fields.
3. Do not let a query-level check count unless it dominates the field resolver.

Acceptance: a public parent, a sensitive field, no guard, reports. `@auth` on that field does not. A literal field does not. Middleware that does not dominate the resolver still reports.

FP risk: a directive that means auth but is not catalogued. The finding stays until a model row names it. That is intended, and the witness is the way out.

### Phase 328 — WebSocket connection auth [`FULLSHIELD_EXPERIMENTAL_WSAUTH`]
A message handler that reaches a sink needs the connection-level predicate from 300 or its own dominating check. A check on one event does not cover siblings. Listeners registered before auth runs are not covered. Listeners added inside the auth success continuation are covered. Emit `SAST-WS-AUTH-001` (high) with the event name. Do not rediscover `socket.on`.

Depends on: 300, 311. Flag off: byte-identical.

Build:
1. Read the connection predicate and the per-event predicate.
2. Apply 307's earlier-and-dominating rule.
3. Skip handlers that reach no sink.

Acceptance: a SQL-reaching handler behind connection auth emits nothing. A sibling without auth reports. An ack-only handler does not. Auth registered after `on` reports.

FP risk: a public echo socket. It has no store sink, so it does not report. The negative fixture is that echo.

### Phase 329 — Debug and docs routes [`FULLSHIELD_EXPERIMENTAL_DEBUGROUTE`]
Paths on a closed catalog (`/metrics`, GraphQL playground paths, `/docs`, `/swagger`, `/debug`, stack-dump handlers) with auth predicate `none` are `CONFIG-DEBUG-ROUTE-001`. Severity is medium unless a dominating literal sets the environment to `development` or `test`, in which case it is info. Unknown environment stays medium. Match `fullPath` after mounts, using the route compiler. `/documentation` does not match `/docs`. A playground middleware mount is the same finding.

Depends on: 255, 311. Flag off: byte-identical.

Build:
1. Compare compiled paths to the catalog. Do not use `includes`.
2. Read environment literals from assignments.
3. Emit one finding per route.

Acceptance: unauthenticated `/metrics` is medium. Authenticated `/metrics` emits nothing. `/docs` under a literal `development` environment is info. `/documentation` does not match.

FP risk: metrics protected only by a proxy. Until 459 links that proxy to the route, the finding stays, and the message says only in-app auth was considered.

### Phase 330 — Access-control matrix report [`FULLSHIELD_EXPERIMENTAL_ACLREPORT`]
`--access-report <path>` writes the 313 matrix plus finding ids from 315, 316, 322, 325, and 327. It adds no findings and does not upload. Unknown cells use the token `unknown` or `not-computed`, never `safe`. The header says the cells are IR edges, not a proof of exposure. Sort is deterministic. Flag off, the option fails with a new `FS-E` code and scan output is unchanged.

Depends on: 313. Flag off: byte-identical scan JSON.

Build:
1. Assemble the document from route records and existing findings.
2. Schema-check the header sentence and the allowed tokens.
3. Write the file only when the option is passed.

Acceptance: the fixture report matches a snapshot. An unknown auth cell is the token `unknown`. Flag off, `scan --json` is unchanged and the file is not created.

FP risk: a reader treating the file as a pentest. The header is in the schema, and the test asserts the sentence is present.

### Lane K — Secret labels (331–345)

A secret is origin `secret` plus a format id from 332, or `none` when only entropy matched. The raw value is never written to a report, a fixture expectation, or a log. Reports show a prefix and a suffix of at most 4 characters and a sha256 fingerprint (340). Fixtures use synthetic values the format registry marks `synthetic: true`, so a test can match the shape without embedding a live credential.

### Phase 331 — Secret flow tracking [`FULLSHIELD_EXPERIMENTAL_SECRETFLOW`]
Once a literal, an env read of a sensitive name, or a file read matches 332, the value carries origin `secret`. Sinks are: a log call, a response body, a client-bundle define (461), an error object returned to a client (345), and a child-process argument. A server-side read of the same value for a signature is not a sink. The witness names the format id and the sink class. It does not contain the secret. Flow uses the IR, so a secret copied through a helper still reaches the sink. `process.env.NODE_ENV` is not a secret. Names come from the format registry and from config, not from the substring `key` on every variable.

Depends on: 251, 256, 332. Flag off: byte-identical.

Build:
1. Attach origin `secret` at the match site.
2. Query the sink classes above. Do not add a second regex scanner in this phase.
3. Redact the witness. A test fails if the JSON value contains the fixture's synthetic secret.

Acceptance: a matched token interpolated into `logger.info` reports. The same token passed only to an HMAC function does not. A copy through a helper still reports. The JSON does not contain the token.

FP risk: a short fixture string that matches a prefix by accident. 332 requires the length and the alphabet, not the prefix alone. The negative fixture is the prefix followed by `example`.

### Phase 332 — Provider format registry [`FULLSHIELD_EXPERIMENTAL_SECRETFORMAT`]
`models/secret-formats.json` holds only formats with a published grammar: prefix, alphabet, length, and a checksum when the vendor documents one. A row has `id`, `source` (a public doc URL the human pasted; the scanner does not fetch it), and `synthetic` examples used by tests. Rows without `source` fail the schema test. The scanner does not invent a vendor pattern from a sample. A format without a documented checksum stays prefix plus length plus alphabet, and 333 may still reject it. Adding a row is a human edit. Cursor does not add rows from memory in a phase commit.

Depends on: none. Flag off: today's secret rules are unchanged.

Build:
1. Validate the schema, including `synthetic: true` on every example.
2. Match the grammar on literals and on assignments. Do not run the examples against the network.
3. A test asserts no example string appears in source outside the registry and the fixtures that cite the id.

Acceptance: a synthetic example of a documented format matches. The same prefix with the wrong length does not. A row missing `source` fails the schema test. Flag off, the existing secret rule ids behave as they do today.

FP risk: a format whose published grammar collides with a commit hash or a fixture id. The row must set `notBeforeLength` high enough that the collision fixture does not match, and that fixture is part of the row's tests.

### Phase 333 — Entropy model v2 [`FULLSHIELD_EXPERIMENTAL_ENTROPY2`]
Entropy is a documented function, not a trained model. On a candidate span that survived 332's alphabet, compute Shannon entropy over the span, reject spans that are a dictionary word, a hex color, a UUID, or the sha256 of the empty string, and compare to committed thresholds in `quality/entropy-thresholds.json`. The file is human-owned (R1). The phase does not tune the thresholds to make a bench app quiet. A span that 332 already matched does not also need entropy. A span that fails the dictionary reject emits nothing. The witness stores the entropy number and the threshold id, not the span.

Depends on: 332. Flag off: byte-identical.

Build:
1. Implement the function and pin the thresholds.
2. Dictionary is a committed word list in the repo, not a download.
3. A test locks one accepted span and one rejected span per reject reason.

Acceptance: a long random synthetic span reports. `deadbeef` as a color-length hex does not. A UUID does not. Changing a threshold without a human edit to the JSON fails the ownership test the way Phase 67's reviewed-bit test does: Cursor-authored commits in the phase do not edit the threshold file. The phase may add the file once with the initial constants; later edits are human.

FP risk: a high-entropy minified string in application source. Minified files matched by 363's density test are excluded from entropy. The exclusion is the negative fixture.

### Phase 334 — Secrets in structured text [`FULLSHIELD_EXPERIMENTAL_SECRETDOCS`]
YAML, TOML, INI, Java properties, and Jupyter notebooks are parsed and then handed to 332 and 333. Comments are scanned. Notebook output cells are scanned. The parsers are in-tree and do not execute notebook code (R15). A parse failure on one file is a 271 event and the file is scanned as text, so a secret is not hidden by a deliberate syntax error. Keys that 332 marks as sensitive (`password`, `secret`, `token`, plus config) promote the value even when the value would not match a prefix, if the value also passes 333. A key named `password` whose value is `changeme` fails 333 and does not report as a high-entropy secret; it can still match a separate committed denylist of placeholder values at info, and that denylist is finite and in the repo.

Depends on: 332, 333. Flag off: byte-identical.

Build:
1. Parse each format. On failure, fall back to the text scanner and record the event.
2. Feed values and comments to 332 and 333.
3. Do not execute notebook cells.

Acceptance: a synthetic token in a YAML comment reports. The same token in a notebook output cell reports. A broken YAML file with the token still reports, plus the event. `password: changeme` is info only if `changeme` is on the placeholder list.

FP risk: an example value in a schema file that is a synthetic token from the registry. Those files live under `models/` and `test/fixtures/` and are excluded by path. A schema file outside those paths is not excluded.

### Phase 335 — Local git objects [`FULLSHIELD_EXPERIMENTAL_GITOBJECTS`]
Scan loose objects, pack files, stash commits, and the reflog that are already in `.git`, by reading the files. Do not spawn `git`. Do not execute hooks. Object parsing is in-tree, fuel-capped per object, and a corrupt object is a 271 event rather than a crash. Blobs are handed to 332. The finding's file field is the object id and the ref name, not a working-tree path that does not contain the secret. Packed refs are included. Alternates that point outside the repo are not followed (that would be another project's files). Severity matches the working-tree rule. The witness says `git-object`.

Depends on: 332. Flag off: byte-identical.

Build:
1. Parse `.git` enough to list blobs reachable from refs, the stash ref, and the reflog.
2. Cap bytes read. Exhaustion records an event and does not claim the repo is clean.
3. Never spawn a process.

Acceptance: a blob reachable only from the reflog reports when it contains a synthetic token, and the working tree does not. A blob only in an alternate is not read. A corrupt object emits the event and the scan continues. A test asserts `child_process` is not used by this phase's module.

FP risk: a secret in a file the user deleted and can no longer rotate from the path in the finding. The object id is the right location. The message says the blob is not in the working tree.

### Phase 336 — Secrets in test snapshots [`FULLSHIELD_EXPERIMENTAL_SECRETSNAP`]
Jest and Vitest snapshot files are in scope for 332. Severity is info, because the usual case is a recorded fixture, unless the format's checksum matches, in which case severity stays the format's normal severity: a checksummed live-shaped token is not "just a snapshot." 341 can allowlist the fingerprint. Snapshots are not skipped by default. Inline snapshots in test files are the same rule.

Depends on: 332, 341. Flag off: byte-identical.

Build:
1. Detect snapshot files by the framework's filename and by `toMatchInlineSnapshot` arguments.
2. Run 332. Checksummed formats keep their severity. Prefix-only formats drop to info inside snapshots.
3. Apply 341 after the finding exists.

Acceptance: a prefix-only synthetic value in a snapshot is info. A checksummed synthetic value in a snapshot keeps high. An allowlisted fingerprint emits nothing. A snapshot that contains no match emits nothing.

FP risk: a snapshot of a public sample token that has a valid checksum because the vendor's sample does. The registry's `synthetic` examples are allowlisted by id inside `test/` and `examples/`. Other checksum hits stay high.

### Phase 337 — Dockerfile build arguments [`FULLSHIELD_EXPERIMENTAL_DOCKERARG`]
This phase reads Dockerfile text. It does not pull an image, run a build, or scan OS packages (Section 31). `ARG` and `ENV` values that match 332 are secrets. An `ARG` used only in a stage that is not copied into the final stage is info. The same `ARG` copied into the final stage with `COPY --from` or used in a `RUN` that writes a file in the final stage is high. `RUN echo $SECRET` is a log sink (331) at high. BuildKit `--mount=type=secret` is the negative: the value is not in the file.

Depends on: 332, 331. Flag off: byte-identical.

Build:
1. Parse stages and `COPY --from` edges.
2. Track which ARG names reach the final stage.
3. Do not resolve variables by executing the Dockerfile.

Acceptance: an ARG secret that dies with an intermediate stage is info. The same ARG copied forward is high. A BuildKit secret mount emits nothing. `RUN echo` of the ARG is high.

FP risk: a multi-stage file the parser cannot connect. The ARG is treated as reaching the final stage, which is the sound direction, and a 271 event says the stage graph was incomplete.

### Phase 338 — Literal secrets in CI configs [`FULLSHIELD_EXPERIMENTAL_CISECRET`]
GitHub Actions, GitLab CI, CircleCI, Azure Pipelines, and Jenkinsfiles are scanned with 332. `${{ secrets.NAME }}`, GitLab masked variables, and other documented indirection forms are not literals and emit nothing. A literal next to those forms still reports. `echo` of a secret expression is 331's log sink when the expression is a literal; an echo of `${{ secrets.NAME }}` is info, because the runner may redact and this phase does not claim the log is clean. The phase does not call the CI vendor.

Depends on: 332, 331. Flag off: byte-identical.

Build:
1. Parse the YAML and the Jenkinsfile enough to find literal scalars and `sh`/`run` strings.
2. Recognize each vendor's secret indirection and do not flag it as a literal.
3. Feed real literals to 332.

Acceptance: a synthetic token in a workflow `env:` reports. `${{ secrets.TOKEN }}` does not. A literal beside a secrets expression reports. Echo of the expression is info.

FP risk: a sample workflow under `docs/` that uses a synthetic example from the registry. The registry synthetic allowlist applies only under `test/fixtures/` and `models/`. A docs sample reports, which is acceptable; the message names the file.

### Phase 339 — Source maps that ship original text [`FULLSHIELD_EXPERIMENTAL_SRCMAPSECRET`]
Parse a source map the repo contains, or a `sourceMappingURL` that points at a file in the repo. Do not fetch a remote map (R15). If `sourcesContent` contains a 332 match, report it at the original path when the map gives one, else at the map file. Also report, at info, a map whose sources are absolute paths outside the repo, because that leaks a developer machine layout. Do not execute the generated JavaScript. A map larger than the fuel cap records a 271 event and is not called clean.

Depends on: 332. Flag off: byte-identical.

Build:
1. Find maps and `sourceMappingURL` comments that resolve inside the repo.
2. Parse JSON. On failure, record the event and do not throw away a sibling map.
3. Scan `sourcesContent` and source path strings.

Acceptance: `sourcesContent` with a synthetic token reports, and the working-tree file without the token is not required. An external `https://` sourceMappingURL emits nothing from a fetch; it emits info that the URL was not fetched. An absolute path in `sources` is info.

FP risk: a map of a test fixture that intentionally contains the synthetic token. Path exclusion for `test/fixtures/` applies.

### Phase 340 — Fingerprint dedupe [`FULLSHIELD_EXPERIMENTAL_SECRETFINGERPRINT`]
The dedupe key is sha256 of the secret bytes plus the rule id. The path is not part of the key, so two files with the same secret are one finding with two locations. The report stores the hash, a prefix, and a suffix. It does not store the secret. Line drift does not create a second finding. A different secret in the same file does. The hash is not reversible in the report. Logs of the scanner must not print the preimage; a test greps the scanner's own log lines.

Depends on: 332. Flag off: byte-identical, including one finding per location as today.

Build:
1. Compute the fingerprint after redaction is decided, on the original bytes.
2. Group locations. Sort them.
3. Forbid the preimage in every output channel the phase touches.

Acceptance: two files, one synthetic secret, one finding, two locations. Two secrets in one file, two findings. The JSON does not contain the secret. Flag off, the two files are two findings as today, and that difference is behind the flag (`DIFF.txt` only if this is ever promoted).

FP risk: two different secrets that truncate to the same prefix and suffix. They remain two findings because the hash differs. The test uses a pair with the same four-character edges and different middles.

### Phase 341 — Fingerprint allowlist [`FULLSHIELD_EXPERIMENTAL_SECRETALLOW`]
`.fullshield/secret-allow.json` contains fingerprints, an optional `until` date, a reason, and a rule id. It must not contain a value that 332 matches; the loader rejects the file with `FS-E` if it does. An entry past `until` is ignored and `SUPPRESS-EXPIRED` is phase 429's job if that phase is on; this phase itself just stops honoring it. A fingerprint that matches no current finding is kept and not reported as a secret. The file is local. It is not sent anywhere.

Depends on: 340. Flag off: the allow file is not read.

Build:
1. Parse the file. Reject raw secrets and unknown rule ids.
2. Drop expired entries.
3. Remove matching findings from the flag-on result only.

Acceptance: an allow entry for the fixture fingerprint removes that finding. A raw token in the allow file fails the load and does not suppress anything. An expired entry does not suppress. Flag off, the finding remains and the file is not read.

FP risk: a hash collision suppressing a different secret. The entry also stores the prefix and suffix, and all three must match. The test is two secrets with the same hash truncated in a broken file; a full sha256 collision is not the test, the prefix check is.

### Phase 342 — Pre-commit budget [`FULLSHIELD_EXPERIMENTAL_PRECOMMIT`]
The hook scans the staged added lines with 332 and the cheap intra-procedural query, not the whole-program IR. Budget is 1 second of wall time, measured, after which the hook prints what it found and exits 0, with a line that the budget stopped the scan. It does not fail closed on budget, because a stuck hook trains people to skip it. A finding found before the budget still exits 1 when `--fail-on` is set. The diff parser is 446's parser when that phase exists; until then the hook shells out to `git diff --cached` and does not execute the project. Paths come from git, and the scanner reads those files itself.

Depends on: 332. Flag off: no hook behavior change.

Build:
1. Parse the cached diff. Scan only added lines plus enough surrounding function for the cheap query, fuel-capped.
2. Enforce the budget with a timer that stops new files. In-flight file results are kept.
3. Exit policy as above. A test uses a large fixture and a stub timer.

Acceptance: a synthetic token on an added line exits 1. The same token on an unchanged line exits 0. A budget trip exits 0 and the output contains the budget line. The project is not executed.

FP risk: a partial line that becomes a secret only after the whole line is assembled. The hook is allowed to miss that until the full scan. The message in the hook template says it is not the full scan.

### Phase 343 — Encrypted secret recognition [`FULLSHIELD_EXPERIMENTAL_ENCRYPTED`]
sops `ENC[` blocks, git-crypt's binary header, and age armored blocks are recognized and are not passed to 333. A checksummed 332 match inside a file that also has an encrypted block still reports if the match sits outside the encrypted span. The phase does not decrypt. It does not shell out to `sops`. Span parsing is in-tree. An unrecognized armor header is scanned as text.

Depends on: 332, 333. Flag off: byte-identical.

Build:
1. Mark encrypted spans.
2. Run 332 and 333 on the complement of those spans.
3. Do not invoke a decryptor.

Acceptance: a file whose only high-entropy span is an `ENC[` block emits nothing. A synthetic token beside the block reports. A git-crypt header file emits nothing from entropy. A normal source file is unchanged.

FP risk: a string that happens to start with `ENC[` in application source. The recognizer also requires sops's documented metadata keys in the same file. The prefix alone is the negative fixture.

### Phase 344 — Secret-manager calls [`FULLSHIELD_EXPERIMENTAL_SECMGR`]
Calls on the catalog (`getSecretValue`, the AWS and GCP secret clients, Vault read) produce origin `secret-manager`. That origin may flow to server sinks and must not flow to a client bundle (461) or a response body. A literal fallback beside the call (`getSecret() || 'hardcoded'`) is a 332/331 finding on the literal, and the manager call does not launder it. The phase does not contact the manager (R15). Missing credentials are not a finding.

Depends on: 251, 331, 461's sink list even if 461 is off: the client-bundle sink names are shared data. Flag off: byte-identical.

Build:
1. Mark catalog calls as that origin.
2. Forbid the origin at response and client-bundle sinks.
3. Keep analyzing the literal fallback as a normal secret.

Acceptance: a manager value used to sign a request emits nothing. The same value placed in `res.json` reports. `getSecret() || 'synthetic-token'` reports the literal. No network call is made, asserted by the host allowlist test.

FP risk: a wrapper the catalog does not know. It is an ordinary call, so a literal inside it still reports and a returned env value follows 331's env rules. The wrapper is not assumed safe.

### Phase 345 — Secrets in error responses [`FULLSHIELD_EXPERIMENTAL_ERRSECRET`]
An error object that may carry origin `secret`, or `err.stack` sent in a response when the environment is not a development literal, is `SAST-ERRSECRET-001`. A dominating redaction that deletes `stack` and the secret field clears it. A generic `res.status(500).json({ error: 'failed' })` emits nothing. The stack finding is medium. A secret field on the response is high. The phase does not turn off stack traces in development fixtures where the literal environment is `development`.

Depends on: 251, 331. Flag off: byte-identical.

Build:
1. Find response sinks whose value is an error object or a spread of one.
2. Apply the environment literal the way 329 does.
3. Honor a dominating redaction transfer function.

Acceptance: `res.json(err)` with no environment literal reports the stack finding. The same handler under literal `development` does not. An error that includes a secret-labeled field reports high even in development. A redaction that deletes `stack` clears the stack finding.

FP risk: a log of `err.stack` on the server. Logging is 331's log sink only when a secret reaches it. A stack log without a secret is not this finding. The negative fixture is `logger.error(err)`.

### Lane L — Advisory, lock, and package facts (346–380)

These phases read `NpmFacts` (261), the OSV cache, or a file the user passed. They do not add a network host. They do not invent advisory ids (R6). A numeric "score" in an old title is a deterministic table or a count, never a learned model (Section 31, Phase 84).

### Phase 346 — Reviewed vulnerable-function database [`FULLSHIELD_EXPERIMENTAL_ADVDB`]
`models/advisory-symbols.json` grows a review state machine on top of 260. States are `candidate`, `reviewed`, and `rejected`. Only a human commit may set `reviewed` or `rejected`; the same guard as Phase 67 fails the build if the commit author is the automation and the state changed to `reviewed`. `candidate` rows are used only under this flag and the finding says `unreviewed`. `rejected` rows are never used. A row still needs `osvId`, `package`, `affectedExports`, and `source`. The source is a URL or a local path the human supplied. The scanner does not fetch it.

Depends on: 260. Flag off: byte-identical, and `candidate` rows are not read.

Build:
1. Enforce the state machine in the schema.
2. Teach the symbol query to read `reviewed` always when the human has promoted the rule, and `candidate` only under the flag. Promotion is R1 and is not this phase.
3. Keep the author guard.

Acceptance: a `candidate` row produces a flag-on symbol result labeled `unreviewed`. Flag off, it produces nothing. A `rejected` row produces nothing even with the flag on. A commit that flips `reviewed` fails the author guard in the test by running the guard on a fixture commit metadata, not by rewriting git history.

FP risk: a reviewed row whose export name is too generic (`handler`). The schema requires the export path to have at least two segments (`pkg.fn`) or an explicit `generic: true` that forces medium confidence. The short name without that bit fails the schema.

### Phase 347 — Patch-diff candidate symbols [`FULLSHIELD_EXPERIMENTAL_PATCHDIFF`]
`fullshield advisory-symbols --diff <file>` reads a unified diff the user already has. It does not clone and does not fetch. Changed function names and export names become `candidate` rows with `source` set to the local file path and `reviewed` unset. The command prints the rows. It does not write `models/advisory-symbols.json` unless `--write` is passed, and `--write` still writes `candidate` only. A hunk that does not parse as a function writes no row for that hunk. The command does not decide that the diff is a security fix.

Depends on: 346. Flag off: the command fails with `FS-E` and does not read the diff.

Build:
1. Parse the diff. Extract names with the existing parser on the new side of each hunk.
2. Emit candidate rows. Never set `reviewed`.
3. Refuse `--write` if the destination row already exists at `reviewed`.

Acceptance: a fixture diff that renames nothing and changes `parse` emits one candidate for `parse`. A comment-only hunk emits nothing. `--write` on a reviewed row exits non-zero and leaves the file. No network.

FP risk: a mechanical rename of an unrelated function in the same diff. The row is `candidate`, so it cannot change default findings. The message says candidate.

### Phase 348 — Deprecation text linked to cached advisories [`FULLSHIELD_EXPERIMENTAL_DEPLINK`]
If a `deprecated` string contains a `GHSA-`, `CVE-`, or `MAL-` id and that id is in the OSV cache for the same package, the deprecation finding gains `linkedAdvisory`. The id is copied from the string. It is not completed from a prefix and it is not fetched. An id-shaped token that is not in the cache sets `linkedAdvisory: unresolved` and does not create `DEPS-VULN-001`. The deprecation severity is unchanged.

Depends on: 261, the OSV cache. Flag off: byte-identical.

Build:
1. Extract id-shaped tokens with a fixed grammar.
2. Look them up in the cache for that package name.
3. Attach the field. Do not emit a new vulnerability row.

Acceptance: a deprecation string containing a cached GHSA links it. A string containing `GHSA-0000-0000-0000` that is not in the cache is `unresolved` and is not a vuln finding. A string with no id is unchanged.

FP risk: an id mentioned as "not GHSA-…" in the text. The grammar accepts the token anyway, and the link is still just a cache lookup. If the cache contains it, linking it is acceptable; the message quotes the deprecation sentence so a human can see the negation. The phase does not parse negation.

### Phase 349 — Minimal transitive upgrade proposal [`FULLSHIELD_EXPERIMENTAL_MINUPGRADE`]
For each vulnerable lock entry, search the cached packument for the lowest version that is outside every cached OSV range and, if one exists, inside the parent's declared range. If none exists, emit the nested override proposal from 248 using `minFixedVersion` from the cache only. The search is a bounded loop over cached versions, not a new solver dependency and not a network call. No version in the cache means no proposal. The command does not edit the lockfile. Output stays the existing unsafe proposal channel.

Depends on: 248, 261. Flag off: today's proposal is unchanged.

Build:
1. Filter cached versions with the semver helper and the OSV ranges.
2. Prefer a version inside the parent range. Otherwise use 248's override text.
3. Deterministic tie break: lowest version, then the existing order.

Acceptance: a fixture cache with 1.0.0 vulnerable and 1.0.1 fixed, parent range `^1.0.0`, proposes 1.0.1. A parent range that excludes every fix proposes a nested override and not a direct bump. An empty cache proposes nothing and does not invent 1.0.2.

FP risk: a fixed version that is yanked. If the packument marks it unpublished (151), skip it. If 151 is off, the proposal can name it, and the witness says unpublished state was not computed.

### Phase 350 — Bump compatibility table [`FULLSHIELD_EXPERIMENTAL_BUMPRISK`]
Replace any notion of a risk score with a closed table. A proposal is `review` when the bump crosses a major, or when an import in the app names an export that the target version's type declarations or `exports` map no longer has (376's import list, if on). Otherwise the proposal is `mechanical`. The words are the table. There is no weight, no probability, and no ML. The table is printed next to 349's proposal. It does not block the proposal.

Depends on: 349. Flag off: proposals have no compatibility field.

Build:
1. Compare the current version and the proposed version with the semver helper.
2. If type declarations or an exports map are in the cached tarball metadata, test the app's import specifiers against them. If they are not cached, the field is `not-computed`, not `mechanical`.
3. Print the table result.

Acceptance: a major bump is `review`. A patch bump with no missing export is `mechanical`. A missing export on a minor bump is `review`. No cached metadata yields `not-computed`.

FP risk: an export used only through a dynamic specifier. Dynamic specifiers stay `not-computed`. They are not called `mechanical`.

### Phase 351 — Lockfile reproducibility check [`FULLSHIELD_EXPERIMENTAL_REPROLOCK`]
Recompute the resolved version of each direct dependency from the cached packument and the manifest range, and compare it to the lock. A mismatch is `DEPS-REPRO-001` (medium) with both versions in the witness. Do not run `npm ci`. Do not install. `--offline` uses the cache only; a missing packument skips that package with a 271 event and is not a mismatch. Transitive mismatches are listed only when the lock's own integrity edges disagree with the cached packument's dependency ranges (164's data). This phase does not change those edges.

Depends on: 261. Flag off: byte-identical.

Build:
1. Evaluate the manifest range against cached versions.
2. Compare to the locked version.
3. Skip rather than fail when the cache lacks the packument.

Acceptance: a lock version outside the range reports. A lock version equal to the cached resolution emits nothing. A missing cache entry emits the event and no `DEPS-REPRO-001`. No `npm` process is spawned, asserted in the test.

FP risk: a range that uses a dist-tag. The tag is not a version. The package is skipped with an event, matching 132's treatment, and is not called unreproducible.

### Phase 352 — Pull-request dependency flags [`FULLSHIELD_EXPERIMENTAL_DEPRFLAGS`]
On a manifest or lock diff, list added and bumped packages and attach facts already computed: advisory ids, install-script bits, and registry host. The output field is `riskFlags`, an array of closed tokens (`advisory-critical`, `install-script`, `non-registry-host`, `new-direct`). It is not a number and not a score (Section 31). Tokens sort lexicographically. A package with no token is omitted, not given `none`. The command reads the diff and `NpmFacts`. It does not post a comment (Section 31).

Depends on: 261. Flag off: the command fails with `FS-E`.

Build:
1. Parse the diff for dependency changes.
2. Attach tokens from existing facts only.
3. Refuse to emit a numeric score field. A schema test fails if the JSON contains `score`.

Acceptance: a fixture diff that adds a package with an install script yields `install-script` and no number. A bump with no facts yields no row. The schema rejects a `score` key.

FP risk: a lockfile reordering with no version change. Those hunks produce no row. The fixture is a reorder.

### Phase 353 — Lifecycle-script abstract interpreter [`FULLSHIELD_EXPERIMENTAL_SCRIPTABS`]
Interpret install-script text in a tiny domain: string constants, concatenation, `exec` of a constant, `fs` writes of a constant path, and reads of `process.env`. Fuel is 10k steps per script. The interpreter implements the abstract steps; it does not call the script. Findings are the same ids as phases 193–200 when the abstract value shows the dangerous pattern, and the witness is the step list. A script that exceeds fuel or uses `eval` emits a 271 event and falls back to the textual rules, so the textual finding is not lost. 354's folded constants are inputs when that flag is on.

Depends on: 193–200's id list, 261. Flag off: those rules stay textual.

Build:
1. Write the interpreter for the statement subset. Anything else is `unknown` and stops that branch.
2. Feed the resulting constants to the existing rule predicates.
3. Attach the step witness.

Acceptance: a script that builds `curl` by concatenation reports `DEPS-SCRIPT-CURL-001` with a witness of the concat steps. A script that only runs `node scripts/build.js` does not. An `eval` script emits the event and still uses the textual rule. The test asserts the script file was not executed.

FP risk: a constant URL in a comment the interpreter treats as code. The interpreter runs on the parsed statements, not on comments. The comment fixture must not report.

### Phase 354 — Static string folding [`FULLSHIELD_EXPERIMENTAL_DEOBFUSC`]
Fold string operations in lifecycle scripts and package entry files: `+`, `\x` escapes, `String.fromCharCode` of numeric literals, `.split('').reverse().join('')`, and one `Buffer.from(lit, 'base64'|'hex')`. Depth and output length are fuel-capped. Folding that would require `eval` or `Function` stops and emits a 271 event. The folded form is what 353 and 332 see. The original source is not rewritten on disk. A folded string that is not a dangerous pattern is not a finding by itself.

Depends on: 353 for scripts; 332 for secrets. Flag off: no folding.

Build:
1. Implement the fold on the AST subset.
2. Cap length. Exhaustion keeps the unfolded form and records the event.
3. Never call `eval`.

Acceptance: `fromCharCode` of the codes for `curl | sh` reaches the 353 rule when both flags are on. A fold that needs `eval` does not produce a guessed string. A long benign base64 README is capped and is not a secret finding unless 332 matches the unfolded prefix that fitted in the cap, and the witness says the fold was partial.

FP risk: folding a test vector in a package's own test file. Test paths under the package are excluded, matching phase 173's exclusion of `test/`.

### Phase 355 — Local malware-shaped signatures [`FULLSHIELD_EXPERIMENTAL_MALSIG`]
`models/malware-shapes.json` is a list of AST shapes: for example, an install script that reads `.npmrc` and also builds a URL. A shape has an id, a human `source` note, and `reviewed`. Unreviewed shapes emit info only. Reviewed shapes can emit high, and only a human sets `reviewed` (the 346 guard). Fixtures are inert and use `example.invalid`. A shape match is not named as a known campaign. The message says which shape id matched. The phase does not download signatures.

Depends on: 353. Flag off: the file is not read.

Build:
1. Match shapes against the abstract script, not against an executed process.
2. Honor `reviewed` for severity.
3. Schema-reject a shape whose fixture URL is not `example.invalid`.

Acceptance: the npmrc-plus-URL fixture reports info while `reviewed` is false. The same row marked reviewed in a human-owned fixture reports high. A script that only reads `.npmrc` does not match the two-part shape. No network.

FP risk: a legitimate script that reads npm config and posts a log line to an internal host. Unreviewed stays info. Promoting the shape is the human's R1 action, and the FP paragraph in the shape row is required by the schema before `reviewed` can be true.

### Phase 356 — Install-script network destinations [`FULLSHIELD_EXPERIMENTAL_NETDEST`]
Extract hosts from URL literals and from 354-folded strings in lifecycle scripts. Emit `DEPS-SCRIPT-HOST-001` (medium) per host that is not `registry.npmjs.org` and not on the policy allowlist (378). Do not resolve DNS and do not connect. `example.invalid` in fixtures is allowed and does not report when the fixture flag `testFixture` is set; real scans have no such flag. The witness is the host and the script key.

Depends on: 354, 378's allowlist shape. Flag off: byte-identical.

Build:
1. Collect hosts from the abstract strings.
2. Compare to the allowlist. An absent policy file means the allowlist is only `registry.npmjs.org`.
3. Do not fetch.

Acceptance: a script URL on `registry.npmjs.org` emits nothing. A script URL on `downloads.example.invalid` reports the host. No socket is opened, asserted by the test.

FP risk: a documentation URL in a string that is not executed. 353 only hands strings that reach a network or shell API. A URL in a `console.log` is not in that set. The log fixture must not report.

### Phase 357 — Capability policy [`FULLSHIELD_EXPERIMENTAL_CAPPOLICY2`]
When a policy file is present, compare the abstract effects from 353 and 356 (`net`, `fs-write`, `env`, `shell`) to the policy's allowed set for that package or for `*`. An effect outside the set is `DEPS-CAP-POLICY-001` (high). When the policy file is absent, emit nothing. The phase does not create a policy by scanning once and blessing the result. `fullshield policy --init` may print a draft from the current effects, marked `draft: true`, and that draft is not enforced until the human removes the bit.

Depends on: 353, 356, 378. Flag off: the policy is not enforced.

Build:
1. Load the allowed set.
2. Diff effects. One finding per package per effect.
3. Ignore drafts.

Acceptance: a policy that allows `fs-write` and a script that also opens a socket reports the socket only. No policy file, no finding. A draft file is not enforced. The init output contains `draft: true`.

FP risk: an effect in a script branch that is dead. The abstract interpreter is may-analysis, so the dead branch still counts, and the message says may. Tightening to must is not this phase.

### Phase 358 — Packument age buckets [`FULLSHIELD_EXPERIMENTAL_POPPROXY`]
From the cached packument `time` field only, assign a closed bucket: `younger-than-7d`, `younger-than-30d`, or `older`. Version count is printed as a count, not a popularity rank. Download counts are not read, because they are not in the packument this scanner is allowed to store and no new host is added. The bucket is info on direct dependencies. It is not a malware finding and the message says so. Missing `time` yields no bucket.

Depends on: 261. Flag off: byte-identical.

Build:
1. Read `time` from the cache.
2. Apply the two thresholds. They are constants in the phase, not tuned per repo.
3. Emit info with the bucket token.

Acceptance: a packument whose earliest version is 1 day old is `younger-than-7d`. A 40-day-old package emits nothing. A missing `time` emits nothing. The JSON does not contain a field named `popularity` or `score`.

FP risk: a new package the team intentionally published. The finding is info and names the bucket. It does not say the package is untrusted.

### Phase 359 — Publish-cadence buckets [`FULLSHIELD_EXPERIMENTAL_CADENCE`]
From packument `time` entries, compute two documented shapes: more than N versions in the last 7 days, or a gap of at least 180 days followed by a version in the last 7 days. N is 10 and is a constant. Emit info with the shape name. Do not call it an anomaly score. Do not claim compromise. One row per package.

Depends on: 261. Flag off: byte-identical.

Build:
1. Sort the cached timestamps.
2. Match the two shapes.
3. Emit the shape token.

Acceptance: 11 versions in 7 days matches the first shape. A single recent version after years matches the second. A steady monthly release matches neither. The message contains the token and not the word "malicious."

FP risk: a monorepo publish bot that versions 11 packages. The count is per package name, not per day across the registry. The fixture is one package.

### Phase 360 — Repository URL mismatch [`FULLSHIELD_EXPERIMENTAL_REPOMISMATCH`]
Compare the repository URL on the cached packument, the repository URL in the cached tarball `package.json`, and the URL of a git dependency if one exists. A difference after normalizing `git+https`, trailing `.git`, and `ssh` versus `https` is `DEPS-REPO-MISMATCH-001` (medium). The finding lists the two URLs. It does not mention stars, followers, or any count this scanner did not collect. Do not fetch the repository (R15). This is the check behind the old "star-jacking" title: a URL mismatch, nothing else.

Depends on: 261 and the tarball cache. No cache, no finding. Flag off: byte-identical.

Build:
1. Normalize the three URL forms.
2. Compare. Missing tarball cache skips with an event.
3. Keep the word "stars" out of the message. A test asserts that.

Acceptance: two different hosts report. `git+https://github.com/a/b.git` and `https://github.com/a/b` do not. A missing tarball emits the event and no finding. The message does not contain "star."

FP risk: a monorepo package whose repository URL points at the meta-repo while the tarball says the same repo with a directory fragment. Normalize by stripping `#` directory fragments before compare. The fragment fixture must not report.

### Phase 361 — Manifest field mismatch [`FULLSHIELD_EXPERIMENTAL_MANIFESTCONF`]
Compare name, version, `scripts`, and dependency ranges across the lock entry, the cached packument version object, and the cached tarball `package.json`. Each differing field is `DEPS-MANIFEST-MISMATCH-001` (high for name or version, medium for scripts, low for a dependency range) and the witness names the field and both values. Name and version mismatches that 169 already reports are not duplicated; this phase adds `scripts` and dependency-range fields. No tarball cache means those fields are skipped.

Depends on: 169, 261. Flag off: byte-identical.

Build:
1. Diff the fields that are present in the cache.
2. Suppress name and version if 169 fired for that package.
3. Do not install the package to "see what would happen."

Acceptance: a tarball `scripts.install` absent from the packument reports medium. Matching scripts emit nothing. A name mismatch emits only the 169 id when 169 is on, and emits this id when 169 is off, so the bug is not silent. The test covers both flag combinations.

FP risk: a dependency range that npm normalizes (`1.0` versus `1.0.0`). Compare with the semver canonical form. The fixture is that pair and must not report.

### Phase 362 — Time and locale gates [`FULLSHIELD_EXPERIMENTAL_TIMEGATE`]
In a lifecycle script or a package entry file, a branch on `Date`, `process.env.TZ`, `process.env.LANG`, or `Intl` that dominates a sink already in 353's set (net, fs write, process exit, shell) is `DEPS-TIMEGATE-001` (medium). The witness quotes the condition's shape and the sink class. The message does not say the package is protestware. A branch that only changes a log string emits nothing. The phase does not run the branch.

Depends on: 353. Flag off: byte-identical.

Build:
1. Find dominating conditions of the listed shapes.
2. Require a 353 sink in the branch.
3. Emit one row per package.

Acceptance: `if (new Date().getUTCFullYear() > 2020) fetch(...)` reports. The same condition around `console.log` does not. A locale check that exits the process reports. A script with no date API does not.

FP risk: a legitimate "skip on old Node" check that uses `process.version`, which is not in the condition list. The negative fixture uses `process.version` and must not report.

### Phase 363 — Source-less package files [`FULLSHIELD_EXPERIMENTAL_MINIFIED`]
A file in a dependency that is over 50 KB, has a newline ratio below the committed constant, and has no accompanying `.map` in the package is `DEPS-MINIFIED-001` (info). The message says the file could not be reviewed as source. It does not say the file is hostile. The constants live next to the entropy thresholds and are not tuned per repo. Files under `dist/` that also ship `src/` in the same package are info still, one row per package, not per file, listing the count.

Depends on: the tarball cache or `node_modules` already present. Do not install. Flag off: byte-identical.

Build:
1. Measure size and newline ratio on JS files in the cached package.
2. Collapse to one row per package.
3. Exclude the package's own test directory.

Acceptance: one large minified file produces one info row with a count. A package of small files emits nothing. A `.map` beside the file emits nothing for that file. The message does not contain "malicious."

FP risk: a package that ships a browser bundle on purpose. The severity is info. The phase does not fail the build unless a user policy says info fails, which is the user's `--fail-on`.

### Phase 364 — Prebuilt binary hosts [`FULLSHIELD_EXPERIMENTAL_BINHOST`]
From `binding.gyp`, `node-pre-gyp` configuration, and 356's hosts, list download hosts for native binaries. A host other than the package's resolved registry host is `DEPS-BINHOST-001` (medium). Do not download the binary. A `binding.gyp` with no URL emits nothing. The witness is the host and the file.

Depends on: 356's extractor, used here on gyp files even when 356's flag is off; the extractor is shared code. Flag off: byte-identical.

Build:
1. Parse URL literals out of those files. Do not execute gyp.
2. Compare hosts to the registry host on the lock entry.
3. Emit one row per host.

Acceptance: a gyp URL on `registry.npmjs.org` emits nothing. A URL on `files.example.invalid` reports. No download is performed.

FP risk: a GitHub release URL for a well-known optional binary. It still reports, because the phase does not keep a vendor allowlist beyond the registry host. Policy 378 can allow the host. The message says allow it in policy if it is intended.

### Phase 365 — Git dependency commit pin [`FULLSHIELD_EXPERIMENTAL_GITPIN`]
A git dependency whose specifier is a branch, a tag, or a semver range is `DEPS-GITPIN-001` (medium). A 40-hex commit id emits nothing. `semver:` tags are not a pin. The existing 120 id for "is a git dependency" stays; this id is specifically "not pinned." When both would fire, both fire, because the facts differ. The test asserts both ids under both flags.

Depends on: 120's parser. Flag off: 120's output is unchanged and this id is absent.

Build:
1. Classify the specifier.
2. Accept only a full object id.
3. Do not resolve the branch to a commit (that would be a network fetch).

Acceptance: `#main` reports. `#semver:^1.0.0` reports. A 40-hex id does not. A non-git dependency does not.

FP risk: a short SHA. It reports, because it is not a full id. The message says the id is not 40 hex characters.

### Phase 366 — Scoped names that resolve to the public registry [`FULLSHIELD_EXPERIMENTAL_INTERNALPUB`]
If the root package is `private: true` or the dependency name's scope equals the root scope, and the lock `resolved` URL is `https://registry.npmjs.org/...`, emit `DEPS-PUBLIC-SCOPE-001` (medium). The finding says the locked tarball host is the public registry. It does not say the package should not exist, and it does not query npm to find out (the URL is already in the lock). A `resolved` URL on a host in the policy's private-registry list emits nothing. `link:` and `file:` workspace copies emit nothing.

Depends on: 261, 378's host list. Flag off: byte-identical.

Build:
1. Compare scope and privacy to the resolved host.
2. Allow hosts from the policy. With no policy, only non-registry hosts count as private, so a public URL reports.
3. Skip `link:` and `file:`.

Acceptance: a private root depending on `@root/pkg` resolved at `registry.npmjs.org` reports. The same dependency with `link:./packages/pkg` does not. A policy host match does not.

FP risk: a public scope the team publishes on purpose from a private meta-repo. Policy allowlists the scope. The default reports, and the message names the policy key.

### Phase 367 — Private registry configuration [`FULLSHIELD_EXPERIMENTAL_PRIVREG`]
Project `.npmrc` registry URLs must be `https`. An `http://` registry is high. A token embedded in the URL is a secret finding through 332/331 and is also this rule at high, with the token redacted. If a policy allowlist of registry hosts exists, a host outside it is medium. The home-directory `.npmrc` is read only when the existing 139 flag is on; this phase does not widen that read. No login is attempted.

Depends on: 137, 332. Flag off: byte-identical.

Build:
1. Parse registry URLs in the project file.
2. Check the scheme, the embedded userinfo, and the optional allowlist.
3. Redact userinfo in the finding.

Acceptance: `https://registry.example.invalid/` with no userinfo emits nothing when it is allowlisted or when no allowlist exists. `http://` reports. `https://token@host/` reports and the JSON does not contain `token`.

FP risk: a localhost registry over HTTP used in development. Config `allowInsecureRegistryHosts` can include `localhost` and `127.0.0.1` only. Other hosts cannot use that key. The schema rejects other hosts under that key.

### Phase 368 — SBOM field completeness [`FULLSHIELD_EXPERIMENTAL_SBOMFIELDS`]
For each npm component, require name, version, and purl. When the lock has integrity, require the hash (249). The command prints the count of components missing each field. It does not print a grade, a percentage score, or a pass/fail derived from a weight. Exit 0. A missing field is a row in the JSON. This does not add `DEPS-VULN` rows. Flag off, SBOM bytes are unchanged.

Depends on: 249. Flag off: byte-identical SBOM.

Build:
1. Generate the SBOM as today when the flag is off.
2. When the flag is on, fill purl and hash as 249 specifies, then count holes.
3. Schema-ban a `score` field.

Acceptance: a package with integrity has zero missing-hash rows. A package without integrity has a missing-hash row and still has a purl. The output has `counts` and no `score`.

FP risk: none as a vulnerability finding. The risk is a consumer dividing the counts into a percentage and publishing it. The command's stdout header says the counts are not a grade. The test asserts the header.

### Phase 369 — VEX justified by reachability evidence [`FULLSHIELD_EXPERIMENTAL_VEX2`]
A VEX statement this tool emits for "not affected" must cite a reachability class the scanner actually computed: `symbol-not-called`, or `not-imported`, with the witness. A statement without that evidence is not emitted. The tool does not emit "not affected" for `reachability-unknown`. `function-reachable-via-dependency` cannot be "not affected." The user can still write their own VEX; this phase only constrains FullShield's emitter. Validation rejects a file the emitter itself just wrote if a row lacks the evidence field.

Depends on: 259 or the existing reachability classes. Flag off: today's VEX output is unchanged.

Build:
1. Gate the emitter on the class.
2. Copy the witness into the VEX justification detail.
3. Round-trip the file through the validator in the test.

Acceptance: a `not-imported` advisory can be "not affected" with the witness. An `unknown` advisory is omitted from "not affected" and remains in the scan. A reachable advisory is not "not affected." Flag off, the previous emitter's bytes remain.

FP risk: `not-imported` being wrong because of a dynamic import 232 has not seen. When 232 is off, the justification names the reachability engine version and the classes it does not understand, including dynamic import. The text is fixed, and the test asserts it.

### Phase 370 — Fix list ordered by reachability [`FULLSHIELD_EXPERIMENTAL_FIXORDER`]
Sort 349's proposals by a fixed key: runtime-observed if 268 ran, then `function-reachable-via-dependency`, then `reachable`, then `reachability-unknown`, then `not-imported`, then package name. The sort is the feature. No finding is added or removed. The key is documented next to the command. A user who wants advisory severity first can pass `--order severity`, which is the other documented key. There is no third key and no weighted blend.

Depends on: 349. Flag off: the existing order is unchanged.

Build:
1. Implement the two keys.
2. Stable-sort equals by package name.
3. Test both keys on a fixture of five proposals.

Acceptance: the fixture order matches the reachability key exactly. `--order severity` matches severity then name. Flag off, the order matches the previous snapshot.

FP risk: a reader assuming the first row is the most dangerous in a sense the key does not state. The command prints the key name on the first line. The test asserts that line.

### Phase 371 — Pinning policy audit [`FULLSHIELD_EXPERIMENTAL_PINPOLICY`]
If the policy file says `exact` for production dependencies, a manifest range that is not an exact version is `DEPS-PIN-POLICY-001` (info, or the severity the policy sets from a closed list). If the policy is absent, emit nothing. This is distinct from 128, which flags floating ranges as a general rule. When both are on, a range that violates both emits 128's id and this id only if the policy exists; the messages differ (general float versus this policy). The policy cannot set severity to a word outside `info|low|medium`.

Depends on: 378. Flag off: 128 is unchanged and this id is absent.

Build:
1. Read the policy pin mode.
2. Compare manifest ranges for production dependencies.
3. Clamp severity to the closed list.

Acceptance: no policy, no finding. Policy `exact` and range `^1.0.0` reports. Policy `exact` and version `1.2.3` emits nothing. A policy severity of `critical` fails to load.

FP risk: a workspace protocol `workspace:*` that is exact by construction. It is treated as exact. The fixture must not report.

### Phase 372 — Copied vulnerable snippets [`FULLSHIELD_EXPERIMENTAL_SNIPPET`]
Hash a normalized AST of each `reviewed` function body in 346, when the body was supplied by the human in the row (`bodyHash` computed from a local file path on the row, not fetched). Match that hash against function bodies in the application and in vendored files. A match of a function whose AST has at least 40 nodes is `SAST-COPIED-SNIPPET-001` (info). Smaller functions are not hashed, because collisions on tiny helpers are expected. The message says the AST matched a reviewed advisory body and names the osv id. It does not say the copy is exploitable. The body file is the human's. The scanner does not download it.

Depends on: 346. Flag off: no matching.

Build:
1. Normalize identifiers and literals, then hash. The normalization rules are listed in the phase test so they do not drift.
2. Enforce the 40-node minimum.
3. Search app and vendored ASTs. Do not search `node_modules` except paths phase 104 already calls vendored.

Acceptance: a copied body at 40 nodes reports info. A 10-node function with the same hash algorithm applied in the test does not enter the index. A non-matching function emits nothing. No fetch.

FP risk: a familiar idiom that survives normalization. The node minimum and the `reviewed` gate are the controls. Unreviewed rows are not indexed.

### Phase 373 — CDN script tags without SRI [`FULLSHIELD_EXPERIMENTAL_SRITAG`]
In HTML and in JSX, a `<script>` or `<link rel="stylesheet">` whose URL is `https:` and whose tag has no `integrity` attribute is `CONFIG-SRI-001` (low). A same-origin relative URL emits nothing. `http:` is the existing cleartext finding if one exists, and also this id. Do not fetch the URL (R15). A `nonce` without `integrity` still reports, because a nonce is not SRI.

Depends on: the HTML parser used by 282 when on; a tag scanner otherwise. Flag off: byte-identical.

Build:
1. Find the tags.
2. Require `integrity` on cross-origin URLs.
3. Do not connect.

Acceptance: a cross-origin script without `integrity` reports. The same tag with `integrity` does not report this id (374 may still speak about the algorithm). A relative script does not. No socket.

FP risk: a script on a host the team controls. It still reports at low. Policy can allow the host. The default is to report.

### Phase 374 — SRI algorithm grammar [`FULLSHIELD_EXPERIMENTAL_SRICHECK`]
When `integrity` is present, parse the attribute. An unknown algorithm or `sha1` / `sha256` below the documented floor (`sha384` or `sha512`) is `CONFIG-SRI-WEAK-001` (low). Do not download the target to recompute the hash. An optional `--sri-from <dir>` hashes files the user already saved and compares, and that mode never takes a URL. A malformed attribute is medium. The phase does not claim the bytes at the URL match.

Depends on: 373's tag finder. Flag off: byte-identical.

Build:
1. Parse the attribute grammar.
2. Apply the algorithm floor.
3. Implement `--sri-from` on local files only.

Acceptance: `sha512-...` well formed emits nothing. `sha1-...` reports low. A broken attribute reports medium. `--sri-from` on a matching file emits nothing and on a mismatched file reports. A test asserts no HTTP client is constructed.

FP risk: a correctly strong hash of the wrong file. Without `--sri-from`, this phase cannot see that, and the message says the bytes were not checked.

### Phase 375 — Import maps and URL imports [`FULLSHIELD_EXPERIMENTAL_IMPORTMAP`]
An import map in HTML and a specifier that is an `https:` URL in source or in the map are `DEPS-URL-IMPORT-001` (medium) unless that specifier also has an integrity in the import map. A relative specifier emits nothing. Do not fetch the URL. A `data:` URL import is high because the code is inline and unsigned. The witness is the specifier with the query string stripped.

Depends on: none beyond the parser. Flag off: byte-identical.

Build:
1. Parse import maps as JSON. A parse error is a 271 event and the map is not treated as empty of risk: the file still gets a medium finding that the map did not parse.
2. Check specifiers.
3. Do not fetch.

Acceptance: an `https:` specifier without integrity reports. The same specifier with integrity does not. A relative specifier does not. `data:` reports high. A broken map reports medium and the event.

FP risk: a specifier that is `https://registry.npmjs.org` used as a package name string and not as an import. Only import and import-map positions count. A string in a comment does not.

### Phase 376 — Symbol-level unused dependencies [`FULLSHIELD_EXPERIMENTAL_DEADSYM`]
A direct dependency imported by at least one static specifier, whose imported names are all unused and whose import is not a side-effect import (`import 'pkg'`), is `DEPS-UNUSED-SYMBOLS-001` (info). Type-only imports (240) do not count as runtime use and do not by themselves make the dependency used. The phase does not remove the dependency and does not edit the manifest. A dynamic import of the package is `unknown` and emits nothing for that package. The witness lists the unused names.

Depends on: 240 when distinguishing type imports; otherwise type imports count as uses, which avoids a false unused result. Flag off: byte-identical.

Build:
1. Collect static imports and their binding uses in the IR.
2. Ignore side-effect imports.
3. Emit info. Do not propose a deletion in this phase.

Acceptance: `import { a } from 'pkg'` with `a` unused reports info. `import 'pkg'` does not. A type-only import with 240 on does not count as use. A dynamic `import(name)` emits nothing for that package.

FP risk: a package used only for its types in a JSDoc that 240 does not see. Without 240, the import counts as use. The phase prefers the false negative.

### Phase 377 — Duplicate versions with different advisory sets [`FULLSHIELD_EXPERIMENTAL_DUPADV`]
When the lock contains two versions of one name and the cached OSV set for those versions differs, emit `DEPS-DUP-ADVISORY-001` (medium) naming both versions, both lock paths, and the advisory ids that apply to only one. Do not downgrade or drop `DEPS-VULN-001` on the affected version. If the sets are equal, emit nothing. If either set is unknown because the cache is missing, emit nothing and record a 271 event.

Depends on: 261, OSV cache. Flag off: byte-identical.

Build:
1. Group lock entries by name.
2. Diff the cached advisory id sets.
3. Leave vuln rows untouched.

Acceptance: 1.0.0 affected and 1.1.0 not, both locked, reports this id and still reports `DEPS-VULN-001` for 1.0.0. Two clean versions emit nothing. A missing cache emits the event only.

FP risk: two versions that are both affected by different ids. The row lists the symmetric difference. It does not say one of them is safe.

### Phase 378 — Supply-chain policy file [`FULLSHIELD_EXPERIMENTAL_SCPOLICY`]
`fullshield.policy.json` is the schema for allowed registries, allowed script capabilities, pin mode, secret-allow pointers, and private registry hosts. This phase is the loader and the schema. Checks live in the phases that read the policy. An invalid file fails the scan with `FS-E` and no partial enforcement. Unknown keys are errors, not ignored. The loader does not fetch a remote policy URL. A missing file means every consumer behaves as that phase's "no policy" branch specifies.

Depends on: none. Flag off: the file is not read, even if present.

Build:
1. Publish the JSON Schema next to 441's config schema.
2. Fail closed on unknown keys and wrong types.
3. Expose a typed object to later phases.

Acceptance: a valid file loads. An unknown key exits with `FS-E` and no findings from policy consumers. Flag off, a broken policy file does not change scan exit code. A `https://` policy location in config is rejected by the schema.

FP risk: a policy typo that fails the whole scan. That is the chosen behavior, and the error names the key. It is not a vulnerability false positive.

### Phase 379 — Offline OSV file [`FULLSHIELD_EXPERIMENTAL_OSVFILE`]
`--osv-file <path>` reads one JSON document the user already has, in the OSV batch or array shape. Those advisories are the only vulnerability source for that run. The command does not merge them with a silent network refresh. `--offline` is implied. Ids in the file are used as written. Ids not in the file are not invented to fill gaps. A malformed file exits `FS-E` and produces no `DEPS-VULN-001` from memory. The existing network path is unchanged when the option is absent.

Depends on: the OSV parser. Flag off: not applicable; the option requires the flag, else `FS-E`.

Build:
1. Parse the file with the cache parser.
2. Disable the network client for that run. A test asserts no socket.
3. Match packages the same way as the cache.

Acceptance: a file with one GHSA produces that id and no other. An empty list produces no vuln findings even if the network would have some; the test proves the client was not constructed. A malformed file exits `FS-E`.

FP risk: a stale file the user trusts. The output names the file path and the run is marked `advisorySource: file`. It does not say the data is current.

### Phase 380 — Advisory cache age [`FULLSHIELD_EXPERIMENTAL_CACHEAGE`]
Read the mtime of the newest OSV cache object. If it is older than `scan.advisoryMaxAge` (default 48 hours), emit one info row `DEPS-ADVISORY-STALE-001` with the age in hours. Do not refresh in this phase. The existing refresh path is the only refresh. A missing cache emits the same id with `age: null` and does not perform a fetch as a side effect of the check. The row is not a vulnerability.

Depends on: the cache directory. Flag off: byte-identical.

Build:
1. Stat the cache. Do not GET.
2. Compare to the config duration.
3. Emit one row.

Acceptance: a cache touched 1 hour ago emits nothing. A cache touched 72 hours ago emits info with the hours. No cache emits info with null age. A test asserts the HTTP client was not used.

FP risk: a clock skew. The age is computed from the file mtime and `Date.now()`. The message prints both timestamps so a skewed clock is visible. It does not adjust the clock.

### Lane M — Runtime, sharing the catalog (381–405)

Runtime phases live under the runtime entry. They import no scanner module (R14). Shared knowledge is `models/sinks.json` and other JSON the runtime may read. A hook that throws fails open and increments the local counter from 403. Nothing in this lane opens a socket unless the phase says the destination is the user's configured endpoint.

### Phase 381 — RASP hooks generated from the sink catalog [`FULLSHIELD_EXPERIMENTAL_RASPV2`]
Hook installation reads `models/sinks.json` (267): package, member, argument index, class. A hand-written hook file that is not a catalog row fails the consistency test. Adding a sink is a catalog row plus a corpus case, not a new ad hoc wrapper. The attack corpus results stay the ones 267 already requires. The runtime still does not import the scanner; it reads the JSON. Unknown catalog classes are not installed and are logged locally once.

Depends on: 267. Flag off: today's hooks remain.

Build:
1. Generate the install list from the catalog at runtime start.
2. Fail the build if a static sink has no hook and no `runtimeGap`.
3. Keep the corpus green.

Acceptance: a catalog row for a new inert sink installs a hook in the test process and blocks or monitors the corpus payload for that class. Removing the row uninstalls it. A scanner import from `src/runtime` fails the R14 test.

FP risk: a catalog row with the wrong argument index blocking a benign argument. The corpus includes a benign call for each row. A wrong index fails that benign case.

### Phase 382 — Runtime string labels [`FULLSHIELD_EXPERIMENTAL_RTAINT`]
Research mode, off by default. At catalog sources, wrap the string in a boxed value that carries the label set from 256's names. Propagation exists only for catalog functions that declare a transfer (for example, concatenation and template literals inside the hooked `Function` is not done; only explicit catalog transfers). This is not a full interpreter of the process. Unboxed strings lose the label, which is a false negative the phase accepts, and a local counter records the unbox. No payload bytes are stored, only the label bit set and the sink id. Fail open. The box must not change `typeof` in a way that breaks the benign corpus; if it would, the phase stays parked rather than shipping a box that changes application behavior. A test asserts stored events contain no request body.

Depends on: 381. Flag off: no wrapping.

Build:
1. Box at sources. Unbox at sinks with the label check.
2. Propagate only through catalog transfers.
3. Store labels and sink ids only.

Acceptance: a corpus payload that passes through one catalog transfer still blocks. A payload that passes through an uncatalogued helper does not block, and the unbox counter increments. The benign corpus still passes. The event record has no body field.

FP risk: a boxed string rejected by an application `instanceof String` check. If the benign corpus or a dedicated compatibility fixture fails, the phase is parked (S3), not patched by weakening the check.

### Phase 383 — SQL tokenizers at the hook [`FULLSHIELD_EXPERIMENTAL_SQLTOK`]
The runtime SQL hook uses the same lexer as 279, selected by the sink package's dialect row (`pg`, `mysql2`, `sqlite`, `mssql`). A tainted hole that the lexer says is outside a literal, or a literal that the token stream shows is closed early, is the event. A numeric hole stays allowed when 382's label says the char class is digits; without 382, the hook treats every interpolated string as tainted and uses the lexical rule only. The lexer is a JS port shipped as data plus a small interpreter, not a native module. Vectors are shared with 279's tests so the two cannot drift: one file, two runners.

Depends on: 381. 279's vectors are shared data. Flag off: the previous SQL hook remains.

Build:
1. Share the vector file.
2. Select the dialect from the catalog row.
3. Emit an event when the token stream shows a breakout.

Acceptance: a fixture `' OR '1` inside a quote that closes is an event. A bound parameter is not. The same vectors pass in the static 279 test and the runtime test. An unknown dialect uses the generic lexer and records which dialect was missing.

FP risk: a dialect the generic lexer mis-tokenizes, blocking a benign literal. The benign corpus includes one literal query per dialect. A block on that query fails the phase.

### Phase 384 — Mongo operator keys [`FULLSHIELD_EXPERIMENTAL_MONGOOP`]
At catalog Mongo sinks, a filter object whose key set includes `$where`, `$function`, `$accumulator`, or a `$`-key that arrived from a request-labeled field is the event. A static pipeline literal is not. Operator keys copied from a constant object are not. The hook looks at keys, not at a string search of the whole query, so a value that happens to contain the characters `$where` is not an event. Static analysis of the same shape stays in 299; this phase is the runtime backstop when the key set was `Unknown` statically.

Depends on: 381. Flag off: no Mongo key hook beyond what already exists.

Build:
1. Inspect enumerable keys at the sink.
2. Treat request-origin `$` keys as the event.
3. Ignore constant objects.

Acceptance: `req.body` passed as the filter, with a `$where` key in the test request, is an event. A constant `{ status: 'open' }` is not. A value string `$where` under the key `title` is not.

FP risk: a tenant who is allowed to send a `$gt` operator on one field. Config lists allowed operators per route. The default allows none from request-origin keys.

### Phase 385 — `cmd.exe` metacharacters [`FULLSHIELD_EXPERIMENTAL_CMDTOK`]
When the sink is `shell: true` on win32, or the program is `cmd.exe` with `/c`, tokenize with `cmd.exe` rules: `%`, `^`, `&`, `|`, newlines, and quotes. Do not use the POSIX tokenizer from 280 on those sinks. A hole that can introduce those characters is the event. `execFile` without a shell is the 280 option-injection rule only. The tokenizer is shared as vectors so Windows-specific cases are tested on Linux CI by calling the tokenizer directly, and the process-spawn test is `skipIf` not win32 with the reason recorded (R22).

Depends on: 381. Flag off: today's command hook remains.

Build:
1. Implement the cmd tokenizer and its vectors.
2. Select it for the win32 shell sinks.
3. Keep POSIX for the others.

Acceptance: a `%` expansion hole is an event under the cmd tokenizer and is not required to be an event under POSIX. A fixed `execFile` argument list is not an event. The Linux CI runs the tokenizer unit tests.

FP risk: a percent sign in a benign argument that is not passed through `cmd.exe`. The tokenizer is not selected for `execFile`. The negative fixture is `execFile` with an argument that contains `%`.

### Phase 386 — Windows path forms [`FULLSHIELD_EXPERIMENTAL_WINPATH`]
Extend 283's path domain with UNC (`\\server\share`), `\\?\` prefixes, drive-relative paths, alternate data streams (`file:stream`), and 8.3 short names. These survive a naive `path.normalize` and are traversal or escape findings when the abstract path can produce them from a tainted segment. POSIX mode does not emit them. The runtime hook on win32 rejects a resolved path that is UNC or escapes the base. The static half runs on every OS; the hook's process test is skipped off win32 with an R22 comment.

Depends on: 283, 381. Flag off: 283's output is unchanged.

Build:
1. Add the forms to the path abstract domain.
2. Reject them in the win32 hook when they leave the base.
3. Keep POSIX fixtures free of these ids.

Acceptance: a tainted segment that can be `\\server\share` is a finding in the static fixture. `path.basename` still clears it. A POSIX scan of that fixture still reports, because the static domain does not depend on the host OS; the finding's message says the form is a Windows path. The hook test runs on win32.

FP risk: a UNC path that is the application's configured base. If the base itself is UNC, paths under that base are allowed. The fixture sets a UNC base and a child path and must not report.

### Phase 387 — SSRF hook on resolved addresses [`FULLSHIELD_EXPERIMENTAL_SSRF2`]
Static side: 281 plus literals that are IP forms (decimal, hex, octal, IPv6-mapped). A hostname that is not a literal IP is a 271 event statically, because rebinding is not a static fact. Runtime side, only when RASP is on: before the socket connects, resolve the name locally and refuse loopback, link-local, and the cloud metadata address range, using a fixed table in the runtime. The hook does not connect to the address to test it. The hook does not scan the remote host. A redirect is followed only up to the catalog's existing redirect policy; the redirect target is checked with the same table. This is the application checking its own outbound call, not an attack against another machine (Section 31).

Depends on: 281, 381. Flag off: today's SSRF hook remains.

Build:
1. Extend the static URL domain with the IP spellings.
2. Add the runtime resolved-address table. The table is data.
3. Check redirect targets the same way, bounded by the existing redirect cap.

Acceptance: `http://2130706433` is a static finding. `http://169.254.169.254` is a runtime event even if the static string is a hostname that the test resolver maps there (the resolver is injected; no real DNS). A literal `https://example.invalid/x` with a tainted query and a safe host is not a metadata event. The test opens no external socket.

FP risk: an allowed internal host. Config lists hosts that skip the table. The default table has no allows. The metadata address cannot be added to the allow list; the schema rejects it.

### Phase 388 — Deserialization sinks [`FULLSHIELD_EXPERIMENTAL_DESER`]
Catalog sinks: `node-serialize`, `js-yaml` `load` with a schema that constructs functions, and `vm` / `eval` of a value that came from `JSON.parse` or a request body. A yaml load with the safe schema is not a sink. The static finding is the tainted string reaching the sink. The runtime hook refuses the catalog call when the argument is request-labeled (382) or, without 382, when the call is on the catalog and the config says `blockUnknown`. Default is monitor. Pickle and other non-JS formats are out of scope (Section 4.3). The phase does not deserialize the payload in the scanner.

Depends on: 381. Flag off: no new sink.

Build:
1. Add the catalog rows and the safe-schema negative.
2. Static query: tainted string to the sink.
3. Runtime: monitor by default.

Acceptance: `node-serialize` of `req.body` is a finding and a runtime event. `yaml.load` with the safe schema is not. `eval(JSON.parse(req.body))` is a finding. A constant yaml document is not.

FP risk: a yaml parser wrapper the catalog does not mark safe. It stays a sink until a model row says the schema is safe. That is the false-positive control: explicit rows only.

### Phase 389 — Template source as the template [`FULLSHIELD_EXPERIMENTAL_TPLSRC`]
`ejs.render`, `pug.render`, and the other 306 engines are SSTI sinks when the template source string is origin `request`, even if the engine would escape data. Escaping data does not make attacker-controlled template source safe. The static query treats the template argument, not the data argument. The runtime hook refuses a request-labeled template string. A template loaded from a file path under a fixed views directory is not this finding (path traversal is 283). The witness names the argument index.

Depends on: 306, 381. Flag off: today's SSTI rule is unchanged.

Build:
1. Mark the template-source argument on each engine.
2. Query request origin into that argument.
3. Hook the same argument at runtime.

Acceptance: `ejs.render(req.body.tpl, data)` is a finding. `ejs.renderFile('views/a.ejs', { name: req.query.n })` is not this id. A runtime request with a template body is an event. A file render is not.

FP risk: a template string built from a constant plus a user word, where the user word is data. If the user word is interpolated into the template source, it is still source and still reports. The negative fixture passes user data only in the data object.

### Phase 390 — Prototype writes [`FULLSHIELD_EXPERIMENTAL_PROTOFREEZE`]
Static: a write of a tainted key to an object, or a write of `__proto__`, `constructor`, or `prototype`, is the existing prototype finding, and this phase adds the path context when 283-style key classes say the key can be one of those names. Runtime, opt-in: freeze the listed builtins at startup (`Object.prototype`, `Array.prototype`, `Function.prototype`). The freeze is off by default because it breaks packages that patch prototypes. The scanner process is not frozen. The finding lists that freeze is opt-in and can break the app. A test proves `src/` does not call `freeze` on prototypes at import time.

Depends on: 381. Flag off: no freeze, static output unchanged.

Build:
1. Tighten the static key check with the char class when 278 is on; otherwise keep today's key check.
2. Add the opt-in freeze in the runtime, default off.
3. Keep the scanner process unfrozen.

Acceptance: `{}.__proto__` assignment from a request key is a finding. A freeze config of `true` in the runtime fixture prevents a prototype write and the benign corpus for that fixture does not need to patch prototypes. Default config does not freeze. Importing the runtime does not freeze the test process.

FP risk: freezing breaks a dependency. That is why the default is off and the finding text says so. The phase does not flip the default.

### Phase 391 — Credential stuffing shape [`FULLSHIELD_EXPERIMENTAL_CREDSTUFF`]
In the runtime only, count failed logins per source key (the limiter key from 321's catalog, or the client address if no key is configured). More than the config count of failures across more than the config count of distinct usernames in the window is a local event. The response is the application's own 429 from this middleware, not an OS firewall rule and not an IP ban list on the host (Section 31). Counters are process memory unless 392 is on. No event is sent off-box. The static half only checks that a login route has some limiter (that is 321); this phase does not duplicate it.

Depends on: 381. Flag off: no counter.

Build:
1. Count failures in memory.
2. Emit a local event and a 429 when both thresholds are crossed.
3. Reset on the window. Do not persist the counter to disk.

Acceptance: a fixture sequence of failures under the threshold is not a 429. The sequence that crosses both thresholds is a 429. A single username failing many times is 321's limiter, not this event, when the distinct-username count is not met. No socket is opened.

FP risk: a NAT where many users share an address. The threshold defaults are documented and high enough that the test's benign shared-address fixture does not trip. Operators set the numbers. The phase does not learn them.

### Phase 392 — Optional Redis counter store [`FULLSHIELD_EXPERIMENTAL_REDISRL`]
When config selects Redis, the 391 counter may use the `redis` or `ioredis` package if it is installed, as an optional peer (R13). If it is not installed, startup fails with a clear error only when config selects Redis; otherwise the memory counter remains and this package is not imported. The runtime entry does not import the scanner (R14). Keys are the limiter key only. Values are counts. No request body is written to Redis. The host is the user's config, which is an allowed user-configured host (R15), and there is no default host.

Depends on: 391. Flag off: Redis is not imported.

Build:
1. Dynamic `import()` of the client only on the Redis config path.
2. Store counts. Schema-limit the value to an integer.
3. Fall back only when Redis is not selected.

Acceptance: config without Redis does not import the client (test mocks the loader). Config with Redis and no package fails with the install message. A selected client receives the count and not the request body. Scanner modules are absent from the runtime import graph.

FP risk: a Redis key collision with the application's own keys. The key prefix is `fullshield:rl:` and the test asserts the prefix. It is not configurable to empty.

### Phase 393 — Local OpenTelemetry export [`FULLSHIELD_EXPERIMENTAL_OTELLOCAL`]
Optional peer `@opentelemetry/api`. When the user sets an endpoint in config, runtime events may be exported there. The endpoint is a user-configured host (R15), the same class as a webhook. There is no default endpoint and no FullShield-operated endpoint. If the endpoint is unset, the exporter is not constructed and no socket is opened. This is the user's log pipeline. It is not product telemetry, and a test fails if a host literal other than the config value appears in this module (Q8). Flag off, the peer is not imported.

Depends on: 381. Flag off: no export code path.

Build:
1. Import the peer only when the endpoint is set.
2. Send the same local event fields 391 already stores. No source text, no secrets.
3. Assert the unset path opens nothing.

Acceptance: unset endpoint, no import, no socket. Set endpoint, the mock server receives one event without a body or a secret field. A hard-coded host in the module fails Q8.

FP risk: the user pointing the endpoint at a server they did not mean. The endpoint is printed at startup at info. The phase does not discover an endpoint from the environment unless the config names that variable.

### Phase 394 — Per-hook overhead harness [`FULLSHIELD_EXPERIMENTAL_HOOKPERF`]
Dev tooling, not shipped. The harness runs the benign corpus with hooks on and records p50, p95, and p99 per hook into `bench/rasp-overhead.json`, labeled `unreviewed`. It does not change hook behavior. It does not fail CI on a number (that would be a new threshold, R1). It fails CI only if a hook throws. Numbers are whatever the run produced.

Depends on: 381. Not packed (Q12).

Build:
1. Time each hook around the benign corpus.
2. Write the JSON with `unreviewed: true`.
3. Do not edit hook source in this phase.

Acceptance: the file exists after a run and contains one row per catalog hook. A thrown hook fails the harness. A slow hook does not fail it. The file's reviewed bit is false.

FP risk: none for users. The risk is publishing the numbers as a claim. R7 already forbids that until a human reviews them. The harness prints the label.

### Phase 395 — Block-mode canary [`FULLSHIELD_EXPERIMENTAL_CANARY`]
Block mode can apply to a fraction of requests. The fraction is config, default 0, which means monitor for everyone. The choice is a documented hash of the request id the user configures (header name). No request id, no block, monitor only, so the canary cannot be bypassed by omitting the id in order to get a different security decision than a present id: omitting the id never blocks. The hash is not a secret. There is no remote config. The decision is recorded locally.

Depends on: 381. Flag off: block mode is unchanged from the existing config.

Build:
1. Hash the configured request-id header with the documented algorithm.
2. Compare to the fraction.
3. Default 0. Absent header monitors.

Acceptance: fraction 0 never blocks. Fraction 1 blocks the corpus payload. A missing header with fraction 1 monitors and does not block. The same request id always gets the same decision in a test of 20 repeats.

FP risk: a user setting fraction 1 and believing it is a sample. The startup log prints the fraction. The schema rejects a fraction outside 0 to 1.

### Phase 396 — Field-level virtual patches [`FULLSHIELD_EXPERIMENTAL_FIELDPATCH`]
A virtual patch can name a route and a field path (`body.user.role`). The action is `strip` or `block`, from config, not from a downloaded rule. `strip` removes the field before the handler. `block` returns 403. The patch is data. It does not edit source. A path that matches nothing logs locally once and does not block the request. Patches apply only in the runtime. The scanner does not push patches to a client.

Depends on: 381. Flag off: no field patches.

Build:
1. Compile field paths to a walker.
2. Apply `strip` or `block` before the route handler.
3. Ignore unknown paths with one local log line.

Acceptance: a patch stripping `body.role` removes it in the fixture request and leaves `body.name`. A block patch returns 403. An unknown path does not 403. No source file changes.

FP risk: a path that strips a field the handler requires, turning one bug into a 500. The action default is `block`, not `strip`, so the handler does not see a half object unless the user asked to strip. The schema default is `block`.

### Phase 397 — CSP suggestion from literals [`FULLSHIELD_EXPERIMENTAL_CSPBUILD`]
From the route model and from script URLs that are literals in HTML and JSX, print a suggested `Content-Security-Policy` in the report. The suggestion is a comment. It is not installed as a header. Hosts are only literals found in the repo. A dynamic script URL becomes `'strict-dynamic'` left unset and a note that the host was not static. Inline event handlers (282) cause the suggestion to omit `'unsafe-inline'` and to say the inline handler blocks a strict policy. The phase does not claim the policy is complete.

Depends on: 255, 373. Flag off: the report has no CSP block.

Build:
1. Collect literal script and style hosts.
2. Render the suggestion text.
3. Do not set a header in the user's app.

Acceptance: a fixture with one literal CDN script suggests that host. A fixture with an inline handler does not suggest `'unsafe-inline'`. Flag off, the report snapshot has no CSP section. No header is written into the fixture app.

FP risk: a suggested host that is attacker-controlled in a way the literal scan missed. The text says the suggestion is the set of literals, not a policy that was tested. The test asserts that sentence.

### Phase 398 — Upload path and content type [`FULLSHIELD_EXPERIMENTAL_UPLOAD`]
A multipart filename reaching a filesystem sink is a 283 path query. A file later served with a content type taken from the upload is `SAST-UPLOAD-TYPE-001` (high) when the type can be `text/html` or `image/svg+xml`, because that is same-origin script. A serving path that forces `application/octet-stream` or an image type from a finite allowlist is not the finding. The runtime hook rejects a filename that 386/283 says escapes the upload directory, and rejects the two dangerous types unless config allowlists them. The hook does not inspect file bytes for malware.

Depends on: 283, 381. Flag off: no upload hook.

Build:
1. Static query on the filename and on the served type.
2. Runtime reject for escape and for the two types.
3. Do not parse the file body for exploits.

Acceptance: `originalname` inside `path.join(uploadDir, name)` without basename is a path finding. Serving the file with the request's content type `text/html` is the type finding. Forcing `application/octet-stream` is not. The hook rejects `../` in the fixture request.

FP risk: an SVG host that intentionally serves SVG. Config can allow `image/svg+xml`. The default does not. HTML is not allow-listable; the schema rejects `text/html` in the allow list.

### Phase 399 — GraphQL depth and field-count cap [`FULLSHIELD_EXPERIMENTAL_GQLDEPTH`]
The runtime counts selection-set depth and field count using a fixed cost of 1 per field. The caps are config. Over the cap, the request is rejected with the application's error. There is no learned cost model. Introspection fields count. The static phase reports a schema with no limit middleware when 296 sees a GraphQL route and the runtime config is present in the repo and shows no cap. If the runtime config is absent, the static finding is info, not high, because the cap may live in another repo. The phase does not execute the user's resolvers.

Depends on: 296, 381. Flag off: no cap.

Build:
1. Count depth and fields on the parsed document.
2. Compare to config. Default cap is documented (depth 12, fields 200) and applied only when the user turns the hook on. The hook's own default, when the flag is on and no numbers are set, is those constants.
3. Static info when no config is visible.

Acceptance: a document deeper than the cap is rejected in the runtime fixture. A shallow document is not. Cost is 1 per field in the test, not a weighted table. A schema with no visible cap is an info finding.

FP risk: a persisted-query allowlist that is deeper than the cap on purpose. Config can exempt a hash of a persisted query. Unlisted documents still face the cap.

### Phase 400 — WebSocket message cap [`FULLSHIELD_EXPERIMENTAL_WSGUARD`]
The runtime limits message byte size and JSON depth on catalog WebSocket sinks. Over the cap, the message is dropped and a local event is written. A schema on the handler (the 292 shape, if the app passes one into the hook config) validates keys; it does not clear static taint by itself. Caps are config, with documented defaults when the flag is on. The phase does not fuzz a remote socket and does not open one (Section 31).

Depends on: 300, 381. Flag off: no message cap.

Build:
1. Enforce size and depth.
2. Optionally validate against a schema object the user passed.
3. Drop the message. Do not close the process.

Acceptance: a message over the size cap is dropped. A message under it reaches the handler. A JSON depth over the cap is dropped. No outbound socket exists in the test.

FP risk: a binary frame that is large on purpose. Config sets the cap per route. The default is the documented byte count, and the startup log prints it.

### Phase 401 — Response field masking [`FULLSHIELD_EXPERIMENTAL_RESPMASK`]
Config lists field names that must not appear on response objects (`password`, `resetToken`, `secret`, plus user names). The static query reports `res.json(obj)` when the object's must-set or may-set contains such a field from a model IR. The runtime hook, when config `strip: true`, deletes those keys one level deep and in documented nested paths. Default is report-only, `strip: false`, so the hook does not change responses until asked. The hook does not log the stripped value.

Depends on: 298 or a config list, 381. Flag off: no mask.

Build:
1. Static query on response sinks.
2. Runtime strip only when config says so.
3. Never log the value.

Acceptance: `res.json(user)` where the model has `password` reports. A DTO that omitted `password` does not. With `strip: true`, the fixture response has no `password` key and the log line does not contain the password. Default `strip: false` leaves the body unchanged.

FP risk: a field named `password` that is a password-policy enum the client must see. Config can remove the name per route. The default list applies when the route has no override.

### Phase 402 — Hook integrity at startup [`FULLSHIELD_EXPERIMENTAL_HOOKTAMPER`]
At runtime start, hash the hook installer source that shipped in the package and compare it to a constant written at package build time. A mismatch logs a critical line locally and, if config says so, refuses to start. The default is to start anyway and log, so a package manager rewrite does not become an outage without the user opting in. The hash is not sent anywhere. The build constant is updated by the release build, not by a network lookup.

Depends on: 381. Flag off: no hash check.

Build:
1. Compute the hash at build time into a generated file that is packed.
2. Recompute at startup.
3. Log locally. Optional refuse-to-start.

Acceptance: the shipped constant matches a fresh hash in the test. A mutated fixture file logs critical. Default config still resolves the listen callback. `refuseOnMismatch: true` does not listen. No socket except the user's app listen in the success case.

FP risk: a pack step that rewrites whitespace and changes the hash. The hash is over the built file in the tarball, and the release test computes it the same way. A mismatch fails the release test, not the user's first request.

### Phase 403 — Fail-open counters [`FULLSHIELD_EXPERIMENTAL_FAILOPEN`]
Each hook has a local counter of thrown exceptions. After N throws in a window (config, default 50), that hook fail-opens for the rest of the window and a local line is logged. The counter is memory. It is not exported unless 393 is on. A test forces throws and asserts the next request reaches the handler and the log line exists. N is not tuned from production traffic, because there is no telemetry to tune from.

Depends on: 381. Flag off: a throw still fail-opens immediately, which is today's behavior; this phase makes the threshold explicit when the flag is on. Document that split in the phase report so the behavior change is not silent. The flag-on default of 50 is the behavior change and stays behind the flag.

Build:
1. Count throws per hook.
2. Trip fail-open at N.
3. Log locally.

Acceptance: throw 49 times, the hook still runs. The 50th opens it, and the following request is not blocked by that hook. The log line names the hook. No network.

FP risk: an attacker forcing throws to open the hook. The log line is the detection, and 402's integrity check does not cover this. The message in the log says fail-open tripped. The phase does not pretend otherwise.

### Phase 404 — Runtime config validation [`FULLSHIELD_EXPERIMENTAL_RUNCFG`]
Validate the runtime options object against the JSON Schema from 441 at startup. Unknown keys throw `FS-E` with the key name. Contradictions (`block` mode with fraction 0 and no monitor logger, a Redis mode with no URL, a metadata address on the SSRF allowlist) are errors. The process does not listen until validation returns. The schema is the same file the scanner uses for `fullshield config --check` so the two cannot drift.

Depends on: 441's schema file. Flag off: today's option checks remain.

Build:
1. Load the schema. Do not fetch it.
2. Reject unknown keys and the contradictions listed.
3. Refuse to listen on failure.

Acceptance: an unknown key throws `FS-E` and does not listen. A valid object listens. The metadata address on the allowlist throws. The same schema file validates a scanner config fixture and a runtime config fixture.

FP risk: a typo failing startup. That is the intended failure. The error names the key and does not start the server half-configured.

### Phase 405 — Runtime compatibility matrix [`FULLSHIELD_EXPERIMENTAL_RUNTIMECOMPAT`]
A dev test matrix runs the runtime hook's public API on Node 22 and Node 24 against fixture servers of Express, Fastify, and Koa, and against a plain `http.Server`. Next's server is included only if the fixture can run without a network install beyond the existing dev dependencies; otherwise it is listed as not-in-matrix with a reason, not skipped silently. Each cell is pass or a named failure. The matrix file is committed with the versions. A failure is a test failure, not a skip, except the R22 Windows cases already called out by other phases.

Depends on: 381. Not a user-facing flag. The test is the phase.

Build:
1. One fixture server per framework.
2. Run the benign corpus and one attack payload through the hook.
3. Commit `bench/runtime-matrix.json` with versions and results from the run that landed the phase. Later CI re-runs the tests; it does not trust the JSON as a skip list.

Acceptance: the matrix tests pass on the CI Node versions. A framework that throws on the benign corpus fails CI. The JSON is labeled with the date of the run and `unreviewed: true` until a human says otherwise.

FP risk: none for the scanner's users. The risk is skipping a red cell to land the phase. The instruction is to park (S3), not to skip.

### Lane N — Fixes as IR rewrites (406–425)

A fix is an AST edit whose witness no longer verifies (262) after the edit. Text search-and-replace is not a fix. `--apply` still requires a clean git tree. The tool does not run the application to see if the fix worked (Section 31, R15). It re-scans. A rewrite that cannot prove the hole class is safe refuses and leaves the file.

### Phase 406 — Codemod engine [`FULLSHIELD_EXPERIMENTAL_CODEMOD`]
All later fix phases emit edits through one engine: parse, transform, print, re-parse, and require the printed file to parse. The printer is in-tree or an optional peer; it is not a hard dependency (R13). Each edit carries the finding fingerprint and the witness id it claims to kill. The engine does not apply an edit whose re-parse fails. It does not apply an edit when the git status is dirty, unless `--allow-dirty` is absent, which is the default. `--allow-dirty` does not exist. Dirty trees refuse.

Depends on: 262 for the kill check when that flag is on; the engine still refuses an unparsed result without 262. Flag off: `fullshield fix` is unchanged.

Build:
1. Implement parse, transform, print, re-parse.
2. Record the witness id on the edit.
3. Refuse dirty trees and print failures.

Acceptance: a fixture edit that produces unbalanced syntax is refused and the file is unchanged. A clean edit is reported in the dry-run diff. A dirty git status refuses. The test does not use a network.

FP risk: a printer that changes unrelated lines. The diff must be empty outside the edit's range, and a test plants a comment on another line and asserts it survives byte for byte.

### Phase 407 — SQL value holes to placeholders [`FULLSHIELD_EXPERIMENTAL_SQLPARAM`]
When 279 says the hole is a value position, rewrite the concatenation or template into the client library's placeholder form (`$1`, `?`) and move the expression to the parameter list. When 279 says the hole is an identifier, refuse. The refusal message says an allowlist is required and does not emit a patch that quotes the identifier. A hole 279 cannot classify is a refusal. The rewrite is dry-run by default.

Depends on: 279, 406. Flag off: no SQL rewrite.

Build:
1. Require a value-position classification.
2. Emit the placeholder edit for the client the sink catalog names.
3. Refuse identifier and unknown holes.

Acceptance: `db.query('select * from t where id = ' + req.params.id)` with a numeric class becomes a placeholder and the witness no longer verifies as injection. `ORDER BY ${req.query.sort}` is refused and the file is unchanged. An unknown client is refused rather than printed as `?` on a library that uses `$1`.

FP risk: a value hole that is still a second statement because the literal already contains `;`. 279's whole-query class refuses. The fixture is `q; ${x}` and must not be rewritten as safe.

### Phase 408 — Shell string to `execFile` [`FULLSHIELD_EXPERIMENTAL_EXECFILE`]
When 280 splits the command into a static program and argument vector, and no literal contains a shell metacharacter, rewrite `exec` to `execFile` with the array form. A hole that 280 calls a bare word or an option is a refusal unless the edit can insert a `--` before a positional and 280 then says the hole is safe. If the insertion is not enough, refuse. Redirections and pipes in the literal are refusals. The rewrite does not keep `shell: true`.

Depends on: 280, 406. Flag off: no shell rewrite.

Build:
1. Require a 280 split.
2. Emit `execFile(program, argv)`.
3. Refuse shell syntax in the literal.

Acceptance: `exec('git show ' + rev)` is refused or becomes `execFile('git', ['show', '--', rev])` only if 280's fixture for `--` is clean. `exec('ls ' + name)` without a safe split is refused. `exec('cat a | wc')` is refused. A clean `execFile` already in source is not rewritten.

FP risk: a program that treats `--` as a real argument. The edit uses `--` only when the catalog row for that program says it supports end-of-options. `git` is in the catalog. An unknown program is a refusal, not a guess.

### Phase 409 — Path prefix guard [`FULLSHIELD_EXPERIMENTAL_PATHGUARD`]
Insert `path.resolve(base, input)` and the 258 prefix check (`base + path.sep`) when the base is a string literal or a const binding of one. If the base is not that, refuse. Do not invent a base directory. The edit uses `path.basename` only when 283 says the intended operation is a single segment (the upload filename case). A multi-segment relative path does not get `basename`, because that would change the program's meaning; it gets the prefix check or a refusal.

Depends on: 258, 283, 406. Flag off: no path edit.

Build:
1. Require a static base.
2. Choose basename only for the single-segment class.
3. Refuse otherwise.

Acceptance: `path.join(root, req.query.p)` with `root` a literal becomes the prefix-checked form and the witness no longer verifies as a traversal. A base that is `req.query.root` is refused. An upload filename becomes `basename` and the traversal witness dies. The file's other functions are unchanged.

FP risk: a prefix check that uses `startsWith(base)` without the separator. The edit must use the 258 form. A test fails the phase if the printed code matches the known buggy form.

### Phase 410 — Context-correct escaping [`FULLSHIELD_EXPERIMENTAL_CTXESCAPE`]
Insert the sanitizer that 282 says clears the HTML context of the hole. A text node gets the HTML-escape helper. A URL attribute does not get the HTML-escape helper; it gets the URL sanitizer from the catalog or a refusal. A script body is a refusal unless the catalog has a JS-string encoder and 282 says that encoder clears the context. The edit does not wrap a hole in a sanitizer that 282's matrix says is insufficient. If no catalog sanitizer clears the context, refuse.

Depends on: 282, 406. Flag off: no escape edit.

Build:
1. Read the context from 282.
2. Pick the catalog sanitizer that clears it, or refuse.
3. Re-run the matrix on the edited fixture in the test.

Acceptance: a text-node hole gets the HTML escape and the XSS witness dies. `<a href="${x}">` does not get HTML escape; it is refused or it gets the URL sanitizer, and the test asserts it does not get `escapeHtml` alone. A script-body hole with no encoder is refused.

FP risk: double escaping. If the hole is already wrapped in the same sanitizer, emit no edit. The fixture of a double wrap must produce an empty diff.

### Phase 411 — SSRF allowlist wrapper [`FULLSHIELD_EXPERIMENTAL_SSRFWRAP`]
Wrap the fetch in a helper that parses the URL (281) and compares the host to a literal allowlist. The codemod inserts the helper and a constant `const ALLOW = []`. The edit is never marked safe while the array is empty. `--apply` refuses an empty allowlist. Dry-run shows the edit and says the user must fill the list. The helper rejects non-https unless the list entry says so. The helper does not add hosts from the code under scan.

Depends on: 281, 406. Flag off: no wrapper.

Build:
1. Insert the helper and the empty constant.
2. Refuse `--apply` while the list is empty.
3. Do not populate the list from literals in the file. Those literals may be the bug.

Acceptance: dry-run output contains the helper and the refusal reason. `--apply` on an empty list changes nothing. `--apply` after the test fills a literal host applies, and a URL with a different host is the runtime/static finding. The phase does not add `example.invalid` on its own.

FP risk: an allowlist of `''` or `*`. The helper rejects both. The schema of the list is non-empty hosts with dots or localhost. `*` fails the helper's own unit test.

### Phase 412 — Redirect allowlist [`FULLSHIELD_EXPERIMENTAL_REDIRWRAP`]
The same shape as 411 for redirect sinks. The helper allows only relative paths that do not start with `//` and do not contain a scheme, or absolute URLs whose host is on the literal list. An empty list means relative paths only, and that default is safe to apply, unlike SSRF, because a relative redirect does not leave the origin. The edit replaces `res.redirect(req.query.next)` with the helper. A constant redirect target is not rewritten.

Depends on: 406 and the redirect sink catalog. Flag off: no rewrite.

Build:
1. Insert the helper.
2. Default to same-origin relative.
3. Leave constant targets alone.

Acceptance: `res.redirect(req.query.next)` becomes the helper call and the open-redirect witness dies. `res.redirect('/home')` is not edited. A target of `//evil.example` fails the helper in its unit test. `--apply` works with the default relative-only list.

FP risk: an application that intentionally redirects to a partner host. The user adds the host. The codemod does not add it from a comment.

### Phase 413 — NoSQL filter key guard [`FULLSHIELD_EXPERIMENTAL_NOSQLGUARD`]
When a filter object's keys are `Unknown` and a schema or a literal key list exists, insert a pick of those keys before the call. When no key list exists, refuse. Do not insert a "delete every key that starts with `$`" helper as a safe fix by itself when the schema exists, because the schema pick is tighter; the `$` strip is the edit only when the user passes `--strip-operators` and no schema exists, and that edit is marked `review`, not safe. Casts of enumerated fields use the schema types.

Depends on: 299, 406. Flag off: no edit.

Build:
1. Prefer a schema pick.
2. Refuse when no key list exists, unless `--strip-operators` is set.
3. Mark the strip edit `review`.

Acceptance: a schema of `{ id: string }` produces a pick and the operator-injection witness dies. No schema and no flag produces no edit. `--strip-operators` produces an edit marked `review`. A constant filter is not edited.

FP risk: a pick that drops a key the query needs and returns a broader result. The edit is `review` when the schema is partial (`additionalProperties` not false). It is safe only when the schema is closed. The test covers both.

### Phase 414 — Crypto API replacement [`FULLSHIELD_EXPERIMENTAL_CRYPTOFIX`]
Replace `createHash('md5'|'sha1')` used in a security sink (password, signature, token) with the catalog algorithm (`sha256` minimum for a non-password digest, a password hash API for a password field). Replace `Math.random` used to build a token with `crypto.randomBytes`. Do not replace `md5` of a static asset cache key when a config allow names that function; otherwise still emit the edit marked `review`. Do not claim the new algorithm is the user's compliance requirement. The edit is a source change the user applies.

Depends on: 406 and the crypto sink list from phase 96. Flag off: no crypto edit.

Build:
1. Classify the use as password, token, signature, or other, from the sink catalog.
2. Emit the replacement for the first three.
3. Mark `other` as `review`.

Acceptance: `createHash('md5')` on a password field becomes the password-hash API edit and is not marked safe until the edit names `bcrypt`, `scrypt`, or `argon2`. `Math.random` in a token becomes `randomBytes`. An md5 cache key in an allowed function is not edited. A test does not execute the hash as a cracker.

FP risk: replacing a hash that other systems must reproduce. The edit is `review` whenever the hash is compared to a stored value the schema says is an interoperability digest. Password fields are not that class.

### Phase 415 — JWT verify options edit [`FULLSHIELD_EXPERIMENTAL_JWTOPT`]
Insert `algorithms: ['RS256']` only when the key material is a PEM public key or a certificate. Insert `algorithms: ['HS256']` only when the key is an HMAC secret and the existing list is missing. If the key type is unknown, refuse. Never write `none`. If the existing list mixes HMAC and RSA, refuse and say the calls must be split; do not pick one. The edit does not fetch a JWKS.

Depends on: 317, 406. Flag off: no JWT edit.

Build:
1. Require a known key class.
2. Write a one-element algorithms list of the matching family.
3. Refuse mixed and unknown keys.

Acceptance: a public PEM with no `algorithms` gains `['RS256']`. An HMAC secret gains `['HS256']`. A mixed list is refused and the file is unchanged. The printed code does not contain `none`.

FP risk: a key that is RSA-PSS and not RS256. The catalog maps PEM headers to a default, and the edit is `review` when the header is not the common `BEGIN PUBLIC KEY` case the test covers. Unusual headers refuse.

### Phase 416 — Cookie flag edit [`FULLSHIELD_EXPERIMENTAL_COOKIEFLAGS`]
Add missing `httpOnly: true`, `secure: true`, and `sameSite: 'lax'` on `res.cookie` and session cookie options. Do not override an explicit `sameSite: 'none'`; report it instead, because that value is a cross-site choice the user made. Do not set `secure: false`. An explicit `httpOnly: false` on a csrf cookie name (319) is left alone. Other explicit `httpOnly: false` are reported and not flipped.

Depends on: 319, 406. Flag off: no cookie edit.

Build:
1. Add only missing flags.
2. Leave explicit cross-site and csrf choices.
3. Dry-run by default.

Acceptance: a cookie with no options gains the three flags. `sameSite: 'none'` with `secure: true` is not rewritten and is reported. A csrf cookie with `httpOnly: false` is unchanged. The diff does not touch an unrelated cookie that already has the flags.

FP risk: a local HTTP development server that cannot set `secure`. The edit is `review` when the config environment literal is `development`. It is safe to mark only when that literal is absent or is `production`.

### Phase 417 — Helmet and CORS config edit [`FULLSHIELD_EXPERIMENTAL_HELMETFIX`]
Insert the catalog helmet call when 323's route has no helmet and the app is Express. For CORS, do not replace a reflect-origin with a guessed host. Dry-run shows the reflect finding and inserts a literal `origin: ''` that `--apply` refuses until the user replaces it, same rule as 411. A missing CORS middleware is not given `origin: true`. The edit is allowed to add `origin: false` only when the app has no cross-origin route in the route model; otherwise refuse.

Depends on: 323, 406. Flag off: no config edit.

Build:
1. Insert helmet when absent.
2. Refuse to invent an origin.
3. Allow `origin: false` only when no cross-origin literal exists.

Acceptance: an Express app missing helmet gains the call in dry-run. A reflect CORS is not applied with a fake host. `origin: true` is never inserted. An app with a literal foreign script URL does not get `origin: false`.

FP risk: helmet's default breaking a cross-origin setup. The edit is `review`, not safe, and the message says defaults may block the app's own clients. The test asserts the `review` mark.

### Phase 418 — Secret literal to env [`FULLSHIELD_EXPERIMENTAL_SECRETENV`]
Replace a literal that 332 matched with `process.env.NAME`, where `NAME` comes from the format id plus a short hash of the fingerprint, not from the secret. Append `NAME=` to `.env.example` with an empty value. Do not write the secret into `.env`, the example, the diff, or the log. The finding remains until a later scan sees the env read, and the edit does not say the secret was rotated. If `.env.example` is absent, create it with the key and a comment that the value is not stored.

Depends on: 332, 340, 406. Flag off: no edit.

Build:
1. Replace the literal.
2. Update `.env.example` without the value.
3. Scrub the secret from the diff output.

Acceptance: the source contains `process.env` and not the synthetic token. `.env.example` contains the name and not the token. The dry-run diff does not contain the token. A test greps the process output.

FP risk: two secrets in one file getting the same name. The hash suffix differs. The test uses two tokens and asserts two names.

### Phase 419 — Prototype key guard [`FULLSHIELD_EXPERIMENTAL_PROTOKEY`]
When a tainted key is used in an assignment `obj[k] = v`, insert a dominating guard that rejects `__proto__`, `constructor`, and `prototype`, or rewrite the object allocation to `Object.create(null)` when every subsequent operation in the function is an assignment or a read that does not need `Object.prototype`. If the function calls an object method, do not use `Object.create(null)`; use the guard. Refuse if the key is not tainted. Do not freeze prototypes in the user's process from the codemod; that is 390 and it is opt-in runtime.

Depends on: 390's static key list, 406. Flag off: no edit.

Build:
1. Detect the assignment.
2. Prefer the guard when methods are called.
3. Use `Object.create(null)` only in the pure-assignment case.

Acceptance: `obj[req.body.k] = v` gains the guard and the prototype witness dies. A function that then calls `obj.hasOwnProperty` does not get `Object.create(null)`. A constant key `'name'` is not edited.

FP risk: a guard that throws on a legitimate key `constructor` stored as data. The edit is `review` when the object is on a model field tagged as free-form map. It is safe on `{}` literals that are not returned as API data. The test covers the map case.

### Phase 420 — Fix batches [`FULLSHIELD_EXPERIMENTAL_FIXGROUP`]
Group edits into batches by directory and rule id, with a max diff line count from config (default 400). Output is a list of patch files under `.fullshield/fixes/`. The command does not open a pull request, does not push, and does not comment (Section 31). A batch that contains one `review` edit is marked `review`. A batch of only safe edits is marked `safe`. The user applies a batch by id.

Depends on: 406. Flag off: `fix` output is unchanged.

Build:
1. Bin edits by directory and rule.
2. Split a bin that exceeds the line cap.
3. Write patch files. Do not call `git push` or a forge API.

Acceptance: 10 small edits in two directories produce two batches. One `review` edit marks its batch `review`. No network and no `git push`, asserted by the test. The line cap splits a fixture that exceeds it.

FP risk: a batch the user applies as safe that includes a file outside the directory. The patch paths are checked against the batch directory. A path that escapes is a refused batch.

### Phase 421 — Fix verification on the witness [`FULLSHIELD_EXPERIMENTAL_FIXVERIFY2`]
After an edit, re-scan the touched files with the IR and require the previous witness to fail verification. A textual change that still verifies is a failed fix and is not marked safe. The re-scan does not run the app, the tests, or a browser (Section 31). It does not delete the finding from the baseline; the next full scan does that if the finding is gone. Verification of a refused edit is a no-op.

Depends on: 262, 406. Flag off: phase 91's behavior remains.

Build:
1. Re-parse and re-query the witness's sink.
2. Require the witness checker to fail.
3. Do not spawn the project.

Acceptance: the SQL placeholder edit makes the witness fail verification and the fix is eligible to be safe. An edit that only renames a variable leaves the witness valid and the fix is failed. The test asserts no `npm test` and no application process.

FP risk: a witness that fails for an unrelated reason, marking a bad edit safe. The checker must fail at the same sink line with the same rule id, not merely fail somewhere. The test plants a second bug and asserts it does not satisfy the first witness.

### Phase 422 — Fix disposition table [`FULLSHIELD_EXPERIMENTAL_FIXDISP`]
Disposition is a closed table, not a confidence score (Section 31, Phase 84). `safe` requires: the codemod did not refuse, the witness failed verification (421), and the hole class is on the auto-apply list (`sql-value`, `path-prefix`, `html-text`, `cookie-missing-flag`). Every other applied shape is `review`. There is no weight and no fourth state. The JSON field is `disposition`. A schema test rejects a numeric `confidence`.

Depends on: 421. Flag off: no disposition field.

Build:
1. Encode the table.
2. Set the field.
3. Ban numeric confidence in the schema.

Acceptance: the SQL value rewrite is `safe` when 421 passes. The SSRF empty allowlist is absent, not `safe`. The crypto interoperability case is `review`. The JSON has no `confidence` number.

FP risk: adding a hole class to the auto-apply list casually. The list is in this phase's text and changing it is an R10-level product change that needs a human. The test snapshots the list.

### Phase 423 — Terminal fix review [`FULLSHIELD_EXPERIMENTAL_FIXUI`]
A terminal UI lists batches, shows the diff, and asks for a confirmation per batch. Non-interactive `--apply` applies only `safe` batches and refuses `review` batches with a message to use the UI or `--apply-review`. The UI reads stdin. It does not open a network connection and it does not launch a browser. `--yes` is not added.

Depends on: 420, 422. Flag off: non-interactive `fix --apply` stays as it is today for the previous safe set.

Build:
1. Render the diff.
2. Ask per batch.
3. Block `--apply` of `review` batches.

Acceptance: a scripted stdin of "n" applies nothing. A scripted "y" applies a safe batch. `--apply` on a review batch exits non-zero and writes nothing. No browser process and no socket.

FP risk: a user holding down enter. The prompt default is no. Empty stdin is no. The test sends a newline and asserts no write.

### Phase 424 — Fix rollback journal [`FULLSHIELD_EXPERIMENTAL_FIXJOURNAL`]
Each apply appends `.fullshield/fix-journal.json` with the batch id, the forward patch, the reverse patch, and the file hashes before the edit. `fullshield fix --rollback <id>` applies the reverse patch only when the current file hash equals the hash after the forward edit. A file that changed since is refused. The journal does not contain secrets (418's scrub runs first). The journal is local.

Depends on: 406, 418. Flag off: no journal and no rollback command.

Build:
1. Record hashes and both patches.
2. Rollback only on a matching hash.
3. Scrub secrets.

Acceptance: apply then rollback restores the bytes. A one-character edit after apply makes rollback refuse and leave the new character. The journal of a secret edit does not contain the token.

FP risk: a journal in a public git commit. The init template gitignores `.fullshield/fix-journal.json`. The test asserts the gitignore line.

### Phase 425 — SARIF fixes [`FULLSHIELD_EXPERIMENTAL_SARIFFIX`]
When a safe or review edit exists, the SARIF `fixes` property carries the same patch text as the dry-run. The artifact is validated against the SARIF schema the repo already vendors for tests. A review edit is included and its `description` says `review`. A refused edit is omitted. The SARIF file does not contain a secret literal that 418 removed. Flag off, SARIF bytes are unchanged.

Depends on: 406. Flag off: byte-identical SARIF.

Build:
1. Attach patches to the result locations.
2. Validate the schema.
3. Scrub secrets.

Acceptance: a fixture SQL fix appears under `fixes` and the schema validates. A refused identifier hole has no `fixes` entry. Flag off, the SARIF snapshot matches. The token from 418 is absent.

FP risk: a consumer auto-applying every SARIF fix, including `review`. The description text is `review` or `safe` and the test asserts `review` is not labeled `safe`.

### Lane O — Output, policy, and editors (426–450)

These phases add experimental fields or extra files. They do not change the default finding key `(ruleId, file, line, severity)` unless a phase says so, and then it is behind the flag and needs `DIFF.txt` before any promotion. None of them post to a forge, open a pull request, or send telemetry.

### Phase 426 — Local finding history [`FULLSHIELD_EXPERIMENTAL_HISTORY`]
The existing local sqlite store gains a row per fingerprint: first seen, last seen, last state (`open`, `absent`, `suppressed`). A finding that disappears is `absent`. It is not deleted. The store stays on the machine. There is no sync. The history command reads the store and prints counts. It does not phone home. A test asserts the runtime entry does not open the history database (R14).

Depends on: 340's fingerprint when secrets are involved; the finding key otherwise. Flag off: the store schema is unchanged.

Build:
1. Add the state column.
2. Mark absent rows when a scan finishes without that fingerprint.
3. Keep the file local. Document the path.

Acceptance: two scans, the second without the bug, leave one row with state `absent`. A third scan that brings it back sets `open` and keeps the original first-seen time. No network. The runtime package test does not open the file.

FP risk: a fingerprint that changes because the witness changed, looking like a new bug and an absent old bug. 428 defines the fingerprint stability rules. Until 428 is on, the history message says the key includes the line.

### Phase 427 — Local trend report [`FULLSHIELD_EXPERIMENTAL_TREND`]
`fullshield trend` reads the history store and prints counts per rule per scan id. The header says the numbers are local and unreviewed. There is no chart service and no embedded remote image. Output is text or JSON. Empty history prints zero rows and exits 0. The command does not start a scan by itself unless `--scan` is passed, and `--scan` is the normal local scan.

Depends on: 426. Flag off: the command fails with `FS-E`.

Build:
1. Query the store.
2. Print the header.
3. Do not compute a score.

Acceptance: a fixture store with two scans prints two counts. The header contains `unreviewed`. Empty store exits 0. The JSON has no `score` field.

FP risk: a reader publishing the text as a trend claim. The header is the control, and R7 still applies if someone copies it into the README. This phase does not write the README.

### Phase 428 — Refactor-stable fingerprints [`FULLSHIELD_EXPERIMENTAL_STABLEFP`]
The fingerprint ignores the line number. It hashes the rule id, the sink class, the origin, the repository-relative file path, and the witness shape after identifier normalization (372's normalizer). A function moved inside the file keeps the fingerprint. A function moved to another file does not. A changed sink class does not. The algorithm is documented and tested. Baseline matching uses this fingerprint only when the flag is on. Flag off, the baseline key is unchanged, so this phase does not churn the baseline by surprise.

Depends on: 262, 426. Flag off: baseline keys unchanged.

Build:
1. Define the hash input in one function shared by history and baseline.
2. Test a rename, a move across files, and a sink-class change.
3. Keep the flag-off key.

Acceptance: renaming a local variable keeps the fingerprint. Moving the function to another file changes it. Changing SQL to command injection changes it. Flag off, the baseline snapshot matches the previous key.

FP risk: two real bugs in one file collapsing to one fingerprint. The hash includes a disambiguator: the normalized sink expression's shape, not just the file. Two sinks in one function are two hashes in the test.

### Phase 429 — Suppression audit [`FULLSHIELD_EXPERIMENTAL_SUPPRESS`]
A suppression comment or baseline entry needs a reason string, an owner string, and an optional `until` date. A suppression that matches no current finding is `SUPPRESS-ORPHAN` (info). A suppression past `until` is `SUPPRESS-EXPIRED` (medium) and the underlying finding is reported again. A suppression without a reason is `SUPPRESS-BARE` (medium) and does not suppress. The phase does not delete the user's comment. It reports.

Depends on: 426 for expiry dates that use first-seen; the comment parser otherwise. Flag off: today's suppression behavior remains.

Build:
1. Parse reason, owner, and until.
2. Emit the three ids.
3. Honor only suppressions that have a reason and a live date.

Acceptance: a bare comment does not suppress and reports `SUPPRESS-BARE`. An expired date reports `SUPPRESS-EXPIRED` and the finding returns. An orphan reports info. A complete live suppression suppresses and emits nothing else.

FP risk: a date format the parser misreads as already expired. The only accepted format is `YYYY-MM-DD`. Anything else is `SUPPRESS-BARE`. The test uses `10/21/2026` and expects bare, not expired.

### Phase 430 — SARIF taxonomies [`FULLSHIELD_EXPERIMENTAL_SARIFTAX`]
Every rule file maps to one or more CWE ids or to the explicit token `cwe: none` with a one-line reason. SARIF output includes the taxonomy. A rule with neither fails the build of the package. The mapping file is `rules/*.md` front matter, not a second list that can drift. `cwe: none` is allowed for rules that are policy, not weaknesses, and the reason is required. The phase does not claim CWE coverage it did not map.

Depends on: the rule file loader. Flag off: SARIF without the new taxonomy block, bytes otherwise unchanged.

Build:
1. Require the front matter.
2. Emit the taxonomy.
3. Fail the package build on a missing mapping.

Acceptance: a mapped rule appears in the SARIF taxonomy. A fixture rule with no mapping fails the test. `cwe: none` without a reason fails. Flag off, the previous SARIF snapshot holds.

FP risk: a wrong CWE id. The id is data the human reviews. The phase does not auto-assign from the rule's English title. A test rejects a mapper that reads only the title.

### Phase 431 — GitLab report files [`FULLSHIELD_EXPERIMENTAL_GITLABRPT`]
Emit GitLab SAST and dependency-scanning JSON from the same findings, into files the user names. Validate against the schema files committed in the repo. Do not call the GitLab API. Do not post a comment. A finding that does not fit the schema is listed in a sidecar `unmapped.json` and is not dropped silently. Flag off, the files are not written.

Depends on: 430 for CWE when present. Flag off: no GitLab files.

Build:
1. Map fields.
2. Validate.
3. Write `unmapped.json` for the rest.

Acceptance: a fixture scan produces a schema-valid SAST file. A finding with a missing required GitLab field lands in `unmapped.json` and not in the main file as a broken row. No network.

FP risk: a consumer ignoring `unmapped.json` and thinking the main file is complete. The main file's header names the sidecar. The test asserts that.

### Phase 432 — CycloneDX 1.6 [`FULLSHIELD_EXPERIMENTAL_CDX16`]
When the flag is on, SBOM output can request CycloneDX 1.6. The 1.5 path is unchanged when the flag is off or when `--format cyclonedx` is passed without `--spec 1.6`. 1.6 fields are only those the 1.6 spec already defines that this project has data for (purl, hashes, properties for reachability). No invented fields. Validate with the committed schema. A reachability property is omitted when reachability was not computed, not filled with `unknown` presented as a spec enum unless the spec allows it. If the spec's enum does not include our class names, put the class in a namespaced property and document the name.

Depends on: 249. Flag off: 1.5 bytes unchanged.

Build:
1. Add the 1.6 emitter beside 1.5.
2. Validate.
3. Leave 1.5 as the default.

Acceptance: `--spec 1.6` validates. Default output matches the 1.5 snapshot. A component without a hash omits the hash. The test fails if a 1.6 file is emitted with the flag off.

FP risk: a consumer that rejects namespaced properties. The documentation names the property. The emitter does not drop the component to satisfy a stricter consumer.

### Phase 433 — Local signatures for SBOM and VEX [`FULLSHIELD_EXPERIMENTAL_SBOMIGN`]
Sign the SBOM or VEX with Node's crypto, ed25519, using a key file the user passes. Do not generate a key and upload it. Do not copy the private key into the report. The signature file sits next to the SBOM. Verification is `fullshield sbom --verify` and uses the public half the user passes. A missing key exits `FS-E` and writes no signature. No network.

Depends on: the SBOM command. Flag off: no signature file.

Build:
1. Sign the bytes.
2. Write the signature beside the SBOM.
3. Verify in a test with a fixture key that is not a production secret.

Acceptance: verify succeeds on the fixture key. A flipped byte fails verify. A missing key exits `FS-E` and leaves no file. The private key path is not in the SBOM JSON.

FP risk: a user committing the private key. The command's error text, when the key path is inside the repo, warns. It still signs if the user passes `--i-mean-it` is not added. It warns and continues, because refusing would be a new policy. The warning is tested.

### Phase 434 — Offline HTML report [`FULLSHIELD_EXPERIMENTAL_HTMLRPT`]
Write one HTML file with findings, witnesses, and the matrix if present. The file contains no external script, no external stylesheet, and no image URL. The test loads it in a parser and asserts every URL is absent. Inline style is allowed. Script is not allowed; the report is static. Secrets are redacted as in 340. The file is written only when `--html <path>` is passed.

Depends on: 262 for witnesses when present. Flag off: no HTML.

Build:
1. Render the file.
2. Ban URLs and script tags in the output.
3. Redact secrets.

Acceptance: the fixture report has the finding title and no `http` substring. A secret finding's token is absent. Flag off, the command without the flag errors with `FS-E` rather than writing a partial file.

FP risk: a finding message that contains a URL the user scanned, which is data, not a dependency of the report. The ban is on tags and on stylesheet or script URLs, not on the text of a finding that quotes `https://example.invalid`. The test uses a quoted URL in a message and expects the text, and expects no `src=` or `href=` to a host.

### Phase 435 — Summary page [`FULLSHIELD_EXPERIMENTAL_SUMMARY`]
`fullshield summary` prints counts by severity and by module, the top rule ids by count, and a fixed sentence that the counts are unreviewed unless the history row says a human reviewed them. The template is fixed in the repo. It does not take adjectives from the marketing ban list (Section 31). There is no "risk score." Empty results print zeroes. The command reads the last local scan file and does not scan by itself.

Depends on: the scan JSON. Flag off: the command errors with `FS-E`.

Build:
1. Read the last scan.
2. Print the template.
3. Schema-ban a score and ban the marketing words in the template file.

Acceptance: a fixture scan prints the counts and the unreviewed sentence. The template file does not contain the banned words. No score field. Empty input prints zeroes and exits 0.

FP risk: the top-rule list being mistaken for severity. The list header says "by count." The test asserts the header.

### Phase 436 — Language server on stdio [`FULLSHIELD_EXPERIMENTAL_LSP`]
`fullshield lsp` speaks LSP over stdio: `initialize`, `textDocument/diagnostic`, `shutdown`. Diagnostics come from a scan of the open file plus the IR dependencies 269 already knows how to limit, falling back to the single file if 269 is off. This is not an editor extension. No VS Code package is added (Section 31). No telemetry. The process does not listen on a TCP port. A document that fails to parse returns an empty diagnostic list and a log line, not a crash.

Depends on: 251 for multi-file; single-file mode otherwise. Flag off: the subcommand errors with `FS-E`.

Build:
1. Implement the three LSP methods on stdio.
2. Map findings to diagnostics.
3. Bind no TCP port. A test asserts no listen socket.

Acceptance: a fixture file with one SQL finding produces one diagnostic. A clean file produces none. A TCP connect to the process fails. The package exports do not contain a VS Code contribution point. The test reads `package.json` and fails if `contributes` is added.

FP risk: diagnostics drifting from `scan --json`. The test runs both on the fixture and compares the finding keys.

### Phase 437 — MCP tools for routes and witnesses [`FULLSHIELD_EXPERIMENTAL_MCP2`]
Add MCP tools that return the route matrix, one witness, and the proof JSON for a finding id. They call the same functions as the CLI. They do not apply fixes unless the user invokes the existing fix tool, which still dry-runs unless the user passes apply. The tool list is snapshotted in the MCP manifest test (Q5). No new network host. The server binds as the current MCP server does; this phase does not add a public listener.

Depends on: 313, 262. Flag off: the new tools are not registered.

Build:
1. Register the tools.
2. Return the same JSON the CLI writes.
3. Snapshot the manifest.

Acceptance: a client fixture lists the new tools only when the flag is on. A witness request for an unknown id returns a typed error, not an empty success. Apply is not the default. The manifest snapshot matches.

FP risk: a tool description that tells the client to auto-apply. The description says dry-run. The test reads the description string.

### Phase 438 — Hook templates [`FULLSHIELD_EXPERIMENTAL_HOOKTPL`]
`fullshield init` can print hook snippets for husky, lefthook, and the pre-commit framework. The snippets call the 342 command. They are text. They are not runtime dependencies. A test renders each template and compares it to a snapshot. The templates do not download the hook tool. They do not set `git config --global`.

Depends on: 342. Flag off: init's existing output is unchanged.

Build:
1. Add the three templates.
2. Snapshot them.
3. Do not run the installers in the test; only render.

Acceptance: each snapshot contains the pre-commit command and does not contain a URL fetch. Flag off, init's snapshot is unchanged. The rendered husky snippet is a hook file, not a change to `.gitconfig`.

FP risk: a template that uses `sudo` or a global install. The test rejects `sudo` and `npm install -g` in the template bodies.

### Phase 439 — CI templates [`FULLSHIELD_EXPERIMENTAL_CITPL`]
Templates for Jenkins, CircleCI, Azure Pipelines, and Bitbucket Pipelines run `npx fullshield scan --fail-on high` and store SARIF as a job artifact. They do not post comments (Section 31). GitHub Actions stays the existing template. Third-party images are pinned by digest in the template or the template says the user must pin, and an unpinned image fails the template test. The templates do not contain a secret.

Depends on: the SARIF emitter. Flag off: the templates are not written by init.

Build:
1. Add the four files under `templates/`.
2. Assert pin policy and the absence of comment APIs.
3. Do not contact those systems in the test.

Acceptance: each template contains `--fail-on` and an artifact path. None contain `createComment` or an unpinned image. A secret-shaped token in a template fails the test. Flag off, init does not copy them.

FP risk: a template that fails closed on info findings. The flag is `high`, matching the documented default for new templates, and the test asserts the word `high`.

### Phase 440 — Per-package monorepo reports [`FULLSHIELD_EXPERIMENTAL_MONOREPORT`]
One JSON file per workspace package, plus a rollup. Paths inside a package file are package-relative. A finding in a shared package is counted once in the rollup and listed as inherited by dependents, not re-counted. The inherit edge uses the workspace graph, not a guess from directory names. Flag off, the single report is unchanged.

Depends on: the workspace parser from phase 54. Flag off: byte-identical single report.

Build:
1. Split findings by the package that owns the file.
2. Roll up with a set, not a sum, of fingerprints.
3. Record dependents.

Acceptance: a shared package with one finding and two dependents produces one rollup count and two inherit edges. Package-relative paths do not start with `../` escaping the package. Flag off, the single file snapshot matches.

FP risk: a finding in a file outside every package being dropped. It lands in a `_root` report and is counted in the rollup. The test places a file at the repo root.

### Phase 441 — Config JSON Schema [`FULLSHIELD_EXPERIMENTAL_CFGSCHEMA`]
`docs/config.schema.json` is the schema for the scanner config and the runtime config. `fullshield config --check` validates the local file and exits `FS-E` on errors. 404 uses the same file. Unknown keys fail. The schema is drafted by hand in this phase to match the keys the code already reads; it does not invent new product keys. A test loads every fixture config.

Depends on: none. Flag off: `--check` errors with `FS-E` rather than validating with a partial schema. Existing scans do not start requiring the schema until a later promotion.

Build:
1. Write the schema from the keys the code reads.
2. Implement `--check`.
3. Share the file with 404.

Acceptance: a known-good fixture passes. An unknown key fails. The runtime test and the scanner test load the same schema path. A key the code reads that is absent from the schema fails a coverage test that diffs `src` key reads against the schema.

FP risk: a schema that is stricter than the code and rejects a config the current release accepts. Those keys are added as optional. The test uses the current default config file and expects success.

### Phase 442 — Static rule-doc generator [`FULLSHIELD_EXPERIMENTAL_RULEDOCS`]
A dev script turns `rules/*.md` into a directory of HTML files with the same offline constraints as 434. It does not deploy. It does not fetch fonts. The output is gitignored except a snapshot of one page in the test. Q12: the generator is not packed.

Depends on: the rule files. Not a runtime flag.

Build:
1. Render one page per rule.
2. Ban external URLs the way 434 does.
3. Do not add a deploy step.

Acceptance: the fixture rule's HTML contains the rule id and no script tag. The script is not in `package.json` `files`. A missing rule file fails the generator.

FP risk: the HTML being treated as a second source of truth. The page footer says the Markdown file wins. The test asserts the footer.

### Phase 443 — Witness diagrams [`FULLSHIELD_EXPERIMENTAL_EXPLAIN`]
`fullshield explain <fingerprint>` prints the witness as text: source, steps, sanitizers that removed labels, and the sink. The format is fixed. A snapshot test covers one vulnerable-app finding. If the fingerprint is unknown, exit `FS-E`. The command does not highlight by shelling out to a pager that executes the finding text. It writes stdout only.

Depends on: 262. Flag off: the command errors with `FS-E`.

Build:
1. Render the witness.
2. Snapshot one finding.
3. Refuse unknown ids.

Acceptance: the snapshot contains the source file and the sink file from the fixture. An unknown id exits `FS-E`. The output does not contain a secret fixture's raw token when the finding is a secret; it contains the fingerprint.

FP risk: a step list so long it hides the sink. Cap the printed steps at 40 and say the witness was truncated. The full JSON remains available from the scan file. The test uses a long chain and expects the cap line.

### Phase 444 — CODEOWNERS on findings [`FULLSHIELD_EXPERIMENTAL_OWNERS`]
Match the finding's file against the repo's CODEOWNERS. Print the owner. Do not call the GitHub API. A file with no owner is `unowned`. The match uses the last matching pattern, which is the CODEOWNERS rule. A syntax error in CODEOWNERS is `FS-E` and no owner is guessed. Flag off, findings have no owner field.

Depends on: none beyond the scan result. Flag off: no owner field.

Build:
1. Parse CODEOWNERS.
2. Apply the last-match rule.
3. Attach `owner` under experimental fields.

Acceptance: a fixture CODEOWNERS that assigns `*.js` and then overrides one path uses the override. A file outside every pattern is `unowned`. A broken CODEOWNERS exits `FS-E`. No network.

FP risk: an owner name that is a secret. CODEOWNERS is printed as text. The phase does not special-case it. Secret scanning of the file is 332's job if the line matches a format, which an owner token might. That is acceptable and not suppressed here.

### Phase 445 — Fix-by dates in policy [`FULLSHIELD_EXPERIMENTAL_SLA`]
The policy file maps severity to a day count. A finding whose first-seen time is older than that count is `POLICY-SLA-001` (info) and names the days. Dep findings use the OSV `modified` time when the cache has it, else first-seen. The clock is the scan time. The phase does not file a ticket. A missing history store means the age is unknown and the id is not emitted, rather than treating every finding as new or as old.

Depends on: 378, 426. Flag off: no SLA id.

Build:
1. Read the day counts. Reject non-integers.
2. Compare to first-seen or OSV modified.
3. Emit info. Do not change the original finding's severity.

Acceptance: a 40-day-old high finding with a 30-day policy reports `POLICY-SLA-001` and the original severity stays high. A 1-day-old finding does not. No history store emits nothing from this id. A policy value of `asap` fails to load.

FP risk: a first-seen time that resets when the fingerprint changes. 428 is the mitigation when it is on. The message includes which clock was used (`first-seen` or `osv-modified`).

### Phase 446 — Changed-line view [`FULLSHIELD_EXPERIMENTAL_PRLINES`]
`--changed <diff>` limits the findings printed in the human view and in the default JSON for that invocation to findings whose sink line is in the diff's added or context lines, plus findings whose witness passes through an added line. The IR is still built for the whole program, so a new sink of an old source is included. Findings that do not touch the diff are omitted from that invocation's output and remain in the full file when `--json-full` is also passed. This hides untouched issues on purpose, and the header says so. The phase does not post the diff.

Depends on: 262 for the pass-through rule; line intersection otherwise. Flag off: `--changed` keeps today's behavior if it already exists, or errors if it does not. Do not silently narrow today's default scan.

Build:
1. Parse the unified diff.
2. Intersect sinks and witness steps.
3. Print the header that the view is partial.

Acceptance: a new sink of an old source is included. An old finding in an untouched file is omitted. `--json-full` contains both. The header is present. A default scan without `--changed` is byte-identical.

FP risk: a source introduced in the diff that flows to an old sink. The witness-step rule includes it. The test plants that shape.

### Phase 447 — Versioned scan JSON [`FULLSHIELD_EXPERIMENTAL_JSONSCHEMA`]
`docs/scan-result.schema.json` versions the scan document. The `schemaVersion` field is `1` for the current stable fields. Experimental fields live under `experimental` and may disappear in a minor. Removing a stable field is a major (R16a), and `semver-check` gains a clause that diffs the schema's stable required list. This phase adds the schema and the check. It does not bump the package to 2.0.

Depends on: `scripts/semver-check.mjs`. Flag off: the field is still added only when the flag is on, so default JSON stays stable. The schema file exists either way as documentation of the stable output.

Build:
1. Write the schema from the current stable keys.
2. Teach semver-check to diff the required list.
3. Put new fields under `experimental` when the flag is on.

Acceptance: a fixture document validates. Deleting a required key in a scratch schema fails the semver fixture test. Flag off, `scan --json` matches the previous snapshot. `schemaVersion` is not added to default JSON in this phase.

FP risk: a consumer that rejects unknown fields and then meets `experimental` later. The default document gains no new keys in this phase. The test snapshots the keys.

### Phase 448 — Streaming scan API [`FULLSHIELD_EXPERIMENTAL_STREAMAPI`]
The library exports an async iterator that yields findings as they are finished. Order is not sorted. `scan --json` remains sorted and byte-stable. A test consumes the iterator, sorts, and compares to `scan --json` under the same flags. Cancellation stops the walk and does not leave a worker (495) behind. The iterator is experimental and named so a stable import path is not added. Q5 lists it as experimental.

Depends on: the scan pipeline. Flag off: the export is absent.

Build:
1. Yield findings.
2. Document the unsorted order.
3. Test equality after sort, and cancellation.

Acceptance: the sorted iterator output equals the JSON findings. A cancel in the test leaves no child process. Flag off, the export list snapshot does not include the iterator.

FP risk: a user assuming stream order is the JSON order. The type's doc comment says it is not. The API snapshot includes that comment's text.

### Phase 449 — Data-only rule plugins [`FULLSHIELD_EXPERIMENTAL_RULEPLUGIN`]
A plugin is a JSON file of sources, sinks, and sanitizers in the phase 81 schema. The loader rejects a plugin that contains JavaScript, a `require`, or a path outside the directory the user passed. There is no JS hook. A plugin finding uses a rule id the plugin declares, prefixed `USER-`, and the schema rejects ids that do not start with that prefix so a plugin cannot shadow `SAST-SQLI-001`. The plugin is not packed. It is the user's file.

Depends on: 81's schema, 251 when IR queries are on. Flag off: the directory is not read.

Build:
1. Load JSON only.
2. Enforce the id prefix and the path jail.
3. Run the same query engine.

Acceptance: a plugin sink that matches a fixture reports `USER-…`. A plugin file that is `.js` is rejected. A plugin id of `SAST-SQLI-001` is rejected. A path that uses `..` to leave the directory is rejected. Flag off, the fixture reports nothing from the plugin.

FP risk: a sanitizer in the plugin that clears too much. The plugin's sanitizer is the user's data, and the finding's witness names the plugin file. The phase does not bless the sanitizer. A test shows a plugin sanitizer clearing SQL and the witness containing the plugin path.

### Phase 450 — Performance report [`FULLSHIELD_EXPERIMENTAL_PERFREPT`]
`scan --perf <path>` writes per-phase timings and peak RSS to a local JSON file. Findings are unchanged. The file is labeled `unreviewed`. The command does not upload it. Flag off, `--perf` errors with `FS-E` and the scan still runs when the option is omitted. Timings are not added to the finding JSON.

Depends on: none. Flag off: finding bytes unchanged.

Build:
1. Record timings around the existing phases.
2. Write the side file.
3. Leave the finding document untouched.

Acceptance: the side file has one row per phase that ran and `unreviewed: true`. The finding snapshot matches the run without `--perf` except for timestamps that are not in the finding document. No network.

FP risk: the side file being cited as a benchmark. The label is the control. The phase does not edit BENCHMARK.md.

### Lane P — Text of deploy configs (451–465)

These phases read files in the repo. They do not connect to a cluster, a cloud API, or a container daemon. They do not scan images or OS packages (Section 31). A finding is a fact about the text.

### Phase 451 — Dockerfile stage graph [`FULLSHIELD_EXPERIMENTAL_DOCKERFILE`]
Parse the Dockerfile stage graph. Findings: a secret ARG that reaches the final stage (do not duplicate 337 when that flag is on), `npm install` in a stage that copied a lockfile where `npm ci` could run, a final stage with no `USER`, and a `COPY` of `.env`. An intermediate root stage that is not copied forward is info. Do not build or pull an image. A parser failure is a 271 event and is not a clean result. The module does not import `child_process`.

Depends on: 337. Flag off: byte-identical.

Build:
1. Parse stages and `COPY --from` edges.
2. Emit those facts.
3. Do not invoke `docker`.

Acceptance: no `USER` in the final stage reports. `USER node` does not. `COPY .env .` reports. `npm install` beside a copied lockfile reports. `npm ci` does not. A static check fails if this module imports `child_process`.

FP risk: a scratch final stage with no Node. The npm finding requires a copied lockfile or `package.json`. A stage without them does not get the npm finding. It can still get the root finding.

### Phase 452 — Compose services [`FULLSHIELD_EXPERIMENTAL_COMPOSE`]
Parse compose files. Separate ids for `privileged: true`, `network_mode: host`, a docker-socket mount, an `env_file` whose committed file matches 332, and a published port. `${VAR}` with no default is not a literal. `${VAR:-secret}` is a literal and goes through 332. Do not call `docker compose`. A published port on a service that is not the Node app is low. The Node app is identified by the build context or the package name, and that one is medium.

Depends on: 332. Flag off: byte-identical.

Build:
1. Parse the YAML.
2. Emit one id per fact.
3. Do not import a docker client.

Acceptance: each dangerous key has a positive and a negative fixture. A bare `${TOKEN}` does not report as a secret. A default of a synthetic token does. A redis service's published port is low. No daemon call.

FP risk: a socket mount the user intended for a builder service. It still reports. The message names the service. The phase does not keep a per-service allow without a policy key.

### Phase 453 — Kubernetes manifests for the Node workload [`FULLSHIELD_EXPERIMENTAL_K8SMANIFEST`]
Parse YAML that mentions the package name or the Node image. Findings: `runAsUser: 0` or missing `runAsNonRoot` where the spec is otherwise present, `privileged: true`, a `hostPath`, and a missing memory limit at info. `automountServiceAccountToken: true` is high only when the manifest also mounts the token and the command text does not reference it; otherwise info. Do not read `KUBECONFIG` and do not apply anything. Unrendered Helm is a 271 event plus a 332 text scan, not a structural parse.

Depends on: 332. Flag off: byte-identical.

Build:
1. Parse documents.
2. Gate structural findings on the package or image mention.
3. Leave Helm braces as an event.

Acceptance: `runAsUser: 0` reports. `runAsNonRoot: true` does not. `hostPath` reports. A missing memory limit is info. A `{{ }}` file emits the event and still reports a synthetic token. An unrelated manifest stays quiet. The module does not read `KUBECONFIG`.

FP risk: a workload that mentions the package name in a comment. The mention must be in `image` or `command` or a label the catalog lists, not in a comment. The comment fixture must not report.

### Phase 454 — GitHub Actions expression edges [`FULLSHIELD_EXPERIMENTAL_GHAEXPR`]
`${{ github.event.pull_request.title }}` and the other untrusted `github.event.*` fields are origin `gha-event`. A `run:` step that interpolates that origin is `CI-GHA-INJECT-001` (high). `pull_request_target` plus a checkout of the PR head is `CI-GHA-TARGET-001` (high). A cache key that includes a mutable PR ref is `CI-GHA-CACHE-001` (medium). `github.sha` alone is not that list. The expression grammar is a parser, including nested braces. Do not call GitHub. An artifact path of `.env` is info unless the file exists and 332 matches, in which case it is the secret finding.

Depends on: 338. Flag off: byte-identical.

Build:
1. Parse expressions.
2. Taint the untrusted event fields.
3. Emit the three ids.

Acceptance: the PR title inside `run:` reports. `github.repository` does not. `pull_request_target` with the PR head ref reports. A cache key of only `github.sha` does not. No network.

FP risk: a checkout of the PR that the workflow never executes as code. The target finding is about the checkout pair. The message says the risk is executing the PR. It does not say the workflow is already compromised.

### Phase 455 — GitLab CI untrusted inputs [`FULLSHIELD_EXPERIMENTAL_GITLABCI`]
A `script` or `before_script` that interpolates `CI_COMMIT_MESSAGE`, `CI_MERGE_REQUEST_TITLE`, or another name on the committed untrusted list is `CI-GL-INJECT-001` (high). `CI_JOB_ID` is not on the list. The phase does not prove shell quoting; the message says the variable is interpolated. Do not call the GitLab API.

Depends on: the YAML parser. Flag off: byte-identical.

Build:
1. Keep the untrusted names in data.
2. Find interpolations in script arrays.
3. Emit one row per job.

Acceptance: `echo $CI_MERGE_REQUEST_TITLE` reports. `echo $CI_JOB_ID` does not. A name off the list does not. No network.

FP risk: a quoted here-doc that a human considers safe. This phase still reports. Quoting proof is not claimed. The negative fixture is a job id, not a quoted title.

### Phase 456 — Terraform text for the Node deploy [`FULLSHIELD_EXPERIMENTAL_TFNODE`]
Parse an in-tree HCL subset for resources that reference the package. Findings: ingress `0.0.0.0/0` or `::/0` on the app port, a `public-read` ACL on a bucket the same file passes to the app as state, and a `user_data` literal that 332 matches. Do not run Terraform, refresh providers, or download modules. A construct outside the subset is a 271 event and is not assumed safe. A CIDR on a security group the file does not connect to the app is omitted, not guessed.

Depends on: 332. Flag off: byte-identical.

Build:
1. Parse the subset.
2. Emit the three findings.
3. Do not download modules.

Acceptance: `0.0.0.0/0` on port 3000 reports. The same CIDR on an unconnected group does not. A public-read state bucket reports. A synthetic token in `user_data` reports. No provider network.

FP risk: an office range written as the world CIDR. It reports, and the message quotes the CIDR. That is the check.

### Phase 457 — Serverless and SAM resource text [`FULLSHIELD_EXPERIMENTAL_SAMCFG`]
Parse `serverless.yml` and SAM templates. Findings: `Action: '*'` or `Resource: '*'` on the function role, an HTTP event with no auth whose app route has a session predicate (the mismatch), and an environment literal that 332 matches. A public app route paired with a public event is not a mismatch. Do not deploy and do not import an AWS client. An unresolved `!Ref` is an event and is not by itself a public endpoint.

Depends on: 301, 311, 332. Flag off: byte-identical.

Build:
1. Parse the files.
2. Compare events to the route model when both exist.
3. Emit IAM and secret findings from the text.

Acceptance: `Action: '*'` reports. A scoped action does not. An unauthenticated event plus a session route reports the mismatch. A public pair does not. A token literal reports. No AWS client import.

FP risk: a role star that is a comment. Only the IAM statement structure counts. The comment fixture must not report.

### Phase 458 — Vercel and Netlify config [`FULLSHIELD_EXPERIMENTAL_EDGECFG`]
Parse `vercel.json`, `netlify.toml`, and header files. Findings: a redirect target taken from a request parameter, a missing catalog header (`X-Content-Type-Options`, `Referrer-Policy`) at info, and a `NEXT_PUBLIC_` or `VITE_` value that 332 matches unless the format says `publicByDesign`. A redirect to a literal same-site path emits nothing. Do not call the hosting API.

Depends on: 332. Flag off: byte-identical.

Build:
1. Parse the config.
2. Check redirects, headers, and public env names.
3. Do not contact the host.

Acceptance: a query redirect reports. `/home` does not. A missing `Referrer-Policy` is info. A public env with a synthetic token reports. A `publicByDesign` format does not. No network.

FP risk: a header set to an unusual but safe value. If the header is present, do not report it missing. The test sets `Referrer-Policy: no-referrer` and expects silence.

### Phase 459 — Proxy header pairing [`FULLSHIELD_EXPERIMENTAL_PROXYPAIR`]
When the repo has both an nginx config and an app `trust proxy` setting, compare them. Trust plus `$proxy_add_x_forwarded_for` is `CONFIG-PROXY-001` (high) because the client can prepend. An overwrite directive plus trust emits nothing. If only one side exists, emit nothing. Do not connect to nginx. The message says only the in-repo proxy was compared.

Depends on: the config IR for `trust proxy`. Flag off: byte-identical.

Build:
1. Parse the forwarded-header directive.
2. Read the app setting from source.
3. Emit only when both exist.

Acceptance: append plus trust reports high. Overwrite plus trust emits nothing. Trust alone emits nothing. A proxy file alone emits nothing. The message contains the in-repo sentence.

FP risk: a second proxy the file does not show. The sentence is the control. The phase does not claim the whole path is correct.

### Phase 460 — Production source-map flags [`FULLSHIELD_EXPERIMENTAL_PRODMAP`]
Report `CONFIG-SOURCEMAP-001` (low) when a browser build config sets `productionBrowserSourceMaps: true` or a webpack `devtool` that emits a full map, and that assignment is not under a development-only condition. A server-only map key is not in the catalog. Parse the config as an AST. Do not `require` it. A fixture whose config calls `process.exit(1)` at top level must not run.

Depends on: none. Flag off: byte-identical.

Build:
1. Read the catalog keys from the AST.
2. Respect a dominating environment check.
3. Do not execute the config.

Acceptance: the Next flag at top level reports. The same flag inside `NODE_ENV !== 'production'` does not. A server-only key does not. The `process.exit` fixture does not exit the test.

FP risk: a map that is generated and then deleted by a later build step the AST cannot see. The finding is about the flag. The message says the flag is set, not that the file was observed in an artifact. 339 covers observed files.

### Phase 461 — Bundler env inlining [`FULLSHIELD_EXPERIMENTAL_DEFINEENV`]
A client `define`, `envPrefix`, or Next `env` entry that inlines a name on the secret-name list is `SAST-ENV-CLIENT-001` (high). Any other non-public name is medium. `NEXT_PUBLIC_` and `VITE_` are public prefixes. `publicByDesign` formats do not report. A server target emits nothing. Do not read the process environment to fill a value, and redact a value if the config contains one. Do not run the bundler.

Depends on: 332's name list. Flag off: byte-identical.

Build:
1. Read the define table from the AST.
2. Classify the target.
3. Emit on client inlines.

Acceptance: `process.env.SECRET` on a client target reports and the value is absent from the JSON. `NEXT_PUBLIC_API` does not. A server target does not. The test's own environment is not copied into the finding.

FP risk: a publishable key whose format lacks `publicByDesign`. It reports until the format row gains the bit. The witness names the format id or `name-only`.

### Phase 462 — Env example drift [`FULLSHIELD_EXPERIMENTAL_ENVDRIFT`]
Diff literal `process.env.NAME` reads against `.env.example` and the config schema. A read with no example key is info. An example key never read is info, and the message says "no read in the scan set." Do not open `.env`. A computed `process.env[name]` is a 271 event and not a concrete key. Test files are ignored.

Depends on: 441 if a schema exists. Flag off: byte-identical.

Build:
1. Collect literal reads.
2. Diff keys.
3. Do not read `.env`.

Acceptance: `DATABASE_URL` with no example key reports info. An unread example key reports info. A token placed only in `.env` is absent from the output. A computed key emits the event and no invented name.

FP risk: a key used only by a script outside the scan roots. The message's "scan set" wording is the control, and the test asserts those words.

### Phase 463 — Node flags in start scripts [`FULLSHIELD_EXPERIMENTAL_NODEFLAGS`]
Tokenize `scripts.start` and the process-manager command. `--inspect` with no host, or with a non-loopback host, is `CONFIG-INSPECT-001` (high). `--inspect=127.0.0.1` is not. On a script named `dev` or `start:dev`, the same finding is medium. `--insecure-http-parser` is medium. `--eval` of a secret-shaped literal is high. `--no-warnings` is not a finding. Do not spawn the script.

Depends on: 332. Flag off: byte-identical.

Build:
1. Tokenize the command.
2. Apply the table.
3. Do not spawn Node on it.

Acceptance: bare `--inspect` on `start` is high. The same flag on `dev` is medium. Loopback inspect emits nothing. `--no-warnings` emits nothing. The test does not spawn the script.

FP risk: a start script that is wrapped by a dev-only process manager. The script name is the signal. A script named `start` stays high even if the human only uses it locally. The message says the script name was `start`.

### Phase 464 — Permission-model suggestion [`FULLSHIELD_EXPERIMENTAL_PERMMODEL`]
From literal `fs` paths and literal URL hosts in the IR, print a `node --permission` command that allows only those. A dynamic path produces a gap line and does not produce `--allow-fs-read=*`. `--allow-child-process` is included only when the IR contains `child_process`. The command is printed. `--apply` is disposition `review` and is not on the safe list. Do not run the app under the flag.

Depends on: 251. Flag off: no suggestion.

Build:
1. Collect literal paths and hosts.
2. Render the command or a gap.
3. Keep apply at `review`.

Acceptance: reads of `./data` and a fetch of `https://example.invalid` produce those two allows and no child-process allow. `child_process` in the IR adds that allow. `fs.readFile(req.query.p)` produces a gap and no star allow. `--apply` is `review`.

FP risk: a set that is too tight for a dynamic path the gap already named. The gap line is why apply is not safe. The phase does not discover the missing path by running the app.

### Phase 465 — Process manager units [`FULLSHIELD_EXPERIMENTAL_UNITFILE`]
Parse PM2 ecosystem files and systemd units in the repo. Findings: `User=root` or `uid: 0`, an `Environment=` value that 332 matches, and an inspect flag (463). `User=node` with no secret emits nothing. Do not spawn `systemctl` or `pm2`. The module does not import `child_process`. A sample under `docs/deploy` still reports; this phase does not special-case `docs/`.

Depends on: 332, 463. Flag off: byte-identical.

Build:
1. Parse both formats.
2. Emit the three facts.
3. Do not start a service.

Acceptance: `User=root` reports. `User=node` does not. A synthetic token in `Environment=` is redacted in the JSON. An inspect flag reports. No `child_process` import.

FP risk: a unit the user considers an example. It reports, and the path is in the message. Ignoring `docs/` remains the user's existing ignore list, not a hard-coded exception.

### Lane Q — Measurement and release evidence (466–500)

These phases are dev tooling or release checks. They are not packed (Q12). They do not scan an `untouched` holdout and commit the result (B3). They do not invent advisory data (R6). They do not mark their own output `reviewed` (R7).

### Phase 466 — Holdout registry rows [`FULLSHIELD_EXPERIMENTAL_HOLDOUTS`]
Add ten holdout rows to `bench/holdouts.json` with `status: untouched`, a pinned commit, `reviewed: false`, and an empty `firstRunDate`. The human names the repos in the commit that lands the rows. This text does not invent ten repo names (R6). If the human has not named them, the phase is parked (S3), not filled with placeholders. The schema test rejects a results file added in the same commit, a row already marked `tuning` or `seen`, and `reviewed: true`. Scanning is the release process (B3), not this commit.

Depends on: B1. Not packed.

Build:
1. Enforce the schema on new `untouched` rows.
2. Forbid a results JSON for that name in the same commit.
3. Park if the ten names are not supplied.

Acceptance: once ten human-named rows exist, the schema passes. A results file fails the commit check. A `reviewed: true` row fails. Placeholder names are not part of the implementation.

FP risk: scanning the holdout while adding the row. The forbidden results file is the control.

### Phase 467 — Advisory replay on local checkouts [`FULLSHIELD_EXPERIMENTAL_CVEREPLAY`]
`fullshield replay --before <dir> --after <dir> --id <osvId>` scans two directories the user already has. It records whether each finding is only in `--before` (`present-before`), in both (`not-distinguishing`), or only in `--after` (`regressed`). It does not clone, fetch, or choose one finding as the cause of the id. Output is `unreviewed`. The id is a label the user passed.

Depends on: the scanner. Not packed.

Build:
1. Scan both trees with the same flags.
2. Diff finding keys.
3. Print every distinguishing key. Do not attribute one of them to the id.

Acceptance: a SQL bug only in `--before` is `present-before`. The same bug in both is `not-distinguishing`. The OSV client is not constructed. No `git fetch`.

FP risk: an unrelated old-only finding being read as the CVE. The header says the keys are not attributed. The test asserts that sentence and asserts more than one key is listed when the fixture has two.

### Phase 468 — Synthetic witness generator [`FULLSHIELD_EXPERIMENTAL_SYNTH`]
Generate fixtures by planting a source, a sink, and an optional sanitizer. Mark them `synthetic` and write them under `test/fixtures/synthetic/`. The ground-truth loader refuses that directory (B8). The same seed produces the same bytes. The generator does not scrape advisories and does not copy bench apps. Each file starts with a comment that it is synthetic.

Depends on: 251. Not packed.

Build:
1. Emit the three shapes from a seed.
2. Mark them synthetic.
3. Keep them out of `bench/`.

Acceptance: two runs with the same seed match byte for byte. The loader test rejects a synthetic file as ground truth. The comment is present. No network.

FP risk: citing synthetic recall in BENCHMARK.md. This phase does not edit BENCHMARK.md. The loader refusal is the control.

### Phase 469 — CWE fixture index [`FULLSHIELD_EXPERIMENTAL_CWEINDEX`]
Index fixtures by the CWE front matter from 430. Every in-scope rule needs one positive and one negative fixture. `cwe: none` is exempt. A committed out-of-scope list is exempt only with a one-line reason per row. Do not download a CWE database. The test does not judge whether a negative fixture is secretly positive; Q10 remains that check.

Depends on: 430. Not packed.

Build:
1. Read front matter and fixture names.
2. Assert the pairs.
3. Require reasons on exemptions.

Acceptance: a rule missing a negative fixture fails. A `cwe: none` rule does not. An exemption without a reason fails. No network.

FP risk: a vacuous negative fixture. This phase does not detect that. The acceptance text in the report says Q10 is still required, and the test asserts that the phase does not delete Q10.

### Phase 470 — Second-reviewer agreement [`FULLSHIELD_EXPERIMENTAL_KAPPA`]
When two human label files exist, compute Cohen's kappa per rule and print the count beside it. The script does not write labels and does not break ties. One file prints `needs second reviewer` and exits 0. The number is a statistic about the labels, not a README claim (R7). A hand-computed pair in the test must match to two decimal places.

Depends on: phase 76's label format. Not packed.

Build:
1. Compute kappa from the two files.
2. Print the count.
3. Do not write labels or the README.

Acceptance: the hand-computed pair matches. A single file prints the sentence and exits 0. The label files' hashes are unchanged. The count is in the output.

FP risk: a high kappa on two labels. The count is printed. The test uses a pair of size 2 and expects the count `2`.

### Phase 471 — Static benchmark pages [`FULLSHIELD_EXPERIMENTAL_BENCHHTML`]
Render `bench/*.json` that is already on disk into offline HTML, with 434's ban on external scripts and stylesheet URLs. Show the file's `unreviewed` bit and the file mtime. Do not recompute the numbers and do not treat a missing file as zero. Do not run a scan from the generator.

Depends on: 434's HTML constraints. Not packed.

Build:
1. Read the JSON.
2. Render HTML.
3. Leave missing files as empty sections that say `missing`.

Acceptance: a fixture number appears. A missing file's section says `missing` and not `0`. The HTML has no script URL. The generator starts no scan.

FP risk: stale JSON read as current. The mtime is on the page. The test asserts it.

### Phase 472 — Pinned benchmark toolchain [`FULLSHIELD_EXPERIMENTAL_TOOLCHAINPIN`]
`bench/toolchain.json` records Node, npm, and the Semgrep version 263 uses. The differential test exits non-zero before launching Semgrep when the local version differs, and it prints both versions. It does not download the pinned tool. A pin change is a commit whose report says the pin changed. If CI's image does not match, update the pin in the same commit as the image change; do not weaken the compare.

Depends on: 263. Not packed.

Build:
1. Record the versions.
2. Compare before the differential test.
3. Do not install.

Acceptance: a match continues. A mismatch exits non-zero and does not start Semgrep. The test does not open a network connection.

FP risk: a pin that CI cannot run. The fix is to change the pin and the image together, not to skip the check. The script has no skip flag. The test asserts no `--skip`.

### Phase 473 — Comparison from a reviewed map [`FULLSHIELD_EXPERIMENTAL_COMPARE2`]
Generate a comparison table only from rows in `bench/comparison-map.json` whose `reviewed` bit a human set. Omit unreviewed rows. Do not show them as zeroes. If none are reviewed, print `no reviewed comparison rows`. Do not scrape other tools and do not invent counts (R6). Do not rewrite COMPARISON.md in this phase.

Depends on: B7. Not packed.

Build:
1. Read the map.
2. Drop unreviewed rows.
3. Do not construct an HTTP client.

Acceptance: a reviewed row appears. An unreviewed row does not. An empty map prints the sentence. A test fails if the generator file imports an HTTP client. The generator does not set `reviewed`.

FP risk: a wrong reviewed row. That review is R1. The tool does not flip the bit.

### Phase 474 — Miss list from a local advisory file [`FULLSHIELD_EXPERIMENTAL_FNMINE`]
Read a local JSON list of `{id, file, line, class}` the human curated. Match with B5 (class, file, line ±3). In-scope items with no match are misses. Out-of-scope classes are a separate list and are not misses. Output is `unreviewed`. Do not fetch the ids and do not file issues.

Depends on: B4, B5. Not packed.

Build:
1. Scan the local tree.
2. Match with ±3.
3. Print the two lists.

Acceptance: a planted bug the scan finds is not a miss. A planted in-scope bug the scan misses is on the miss list. A finding four lines away is a miss. A finding three lines away is a hit. No network.

FP risk: calling a line-offset miss a scanner failure when B5 would count it as a hit. The ±3 rule is the acceptance, and the four-line fixture locks it.

### Phase 475 — Precision floors per framework [`FULLSHIELD_EXPERIMENTAL_PRECFW`]
Split 265's Wilson bound by the route's framework tag. Floors stay human-owned. The script does not write the floor file. A cell with fewer than 20 labels is `ungated`. `unknown` framework is its own cell and is not dropped. There is no blended precision that hides one bad framework. A cell under its floor fails CI on `next` the same way 265 does.

Depends on: 265, 255. Not packed.

Build:
1. Split labels by framework.
2. Compute the bound.
3. Leave the floor file's bytes unchanged.

Acceptance: a fixture under the floor fails. A fixture over it passes. Nineteen labels are `ungated`. The `unknown` cell is present. The floor file hash is unchanged.

FP risk: misses parked in `unknown`. The cell is reported. The test asserts it is not folded into another framework.

### Phase 476 — Performance numbers page [`FULLSHIELD_EXPERIMENTAL_PERFPAGE`]
Render `bench/perf*.json` with the 471 generator. Do not add a threshold (R1). Do not fail the build because a number is large. Print `unreviewed` when the file says so. A missing file is an empty section, not a zero.

Depends on: 471. Not packed.

Build:
1. Render the perf JSON.
2. Add no limit.
3. Exit 0 regardless of the magnitude.

Acceptance: a fixture number appears. A large number still exits 0. No new threshold file is created. The header says the page is not a gate.

FP risk: the page being used as a gate. The header sentence is the control, and the test asserts it.

### Phase 477 — Parser and IR fuzzer [`FULLSHIELD_EXPERIMENTAL_FUZZPARSE`]
Mutate a seed corpus and feed it to the parser and the IR builder. Fuel caps mutations and time per input. A crash or a hang past the fuel is a failure. A clean parse error is not a failure. Do not execute the mutated program with `node` or `vm` (R15). Do not fetch seeds. The harness kills a case that exceeds fuel and counts it as a failure instead of waiting for the job timeout.

Depends on: 251. Not packed.

Build:
1. Mutate seeds under fuel.
2. Parse and lower to IR.
3. Fail on crash or hang. Do not assert findings.

Acceptance: zero mutations of a good seed still parse. The harness exits 0 on the current seeds if none crash. The mutated source is never passed to `vm`. A hang is a failed case, not a job timeout.

FP risk: a mutator that never reaches the parser. At least one successful parse per seed family is required. Zero successes fail the harness.

### Phase 478 — Lockfile and metadata fuzzer [`FULLSHIELD_EXPERIMENTAL_FUZZLOCK`]
Fuzz the lockfile, packument, and tarball-metadata parsers by mutating JSON and headers. Do not extract a hostile archive beyond the path checks 179 already has. A crash or a hang is a failure. A rejected file is not. Do not spawn `npm` and do not run package scripts. Zero successful parses in a seed family is a failure.

Depends on: 261. Not packed.

Build:
1. Mutate JSON and headers.
2. Parse under fuel.
3. Forbid an `npm` spawn.

Acceptance: the harness exits 0 on seeds that do not crash. A planted crash fails until fixed. The test asserts no `npm` spawn. A mutator that rejects every input fails the family-success check.

FP risk: mutating into a real install. The harness has no install path. The test reads the harness and rejects a `child_process` spawn of `npm`.

### Phase 479 — Node 22 and Node 24 finding diff [`FULLSHIELD_EXPERIMENTAL_NODEDIFF`]
Run the fixture scan on Node 22 and Node 24 and diff the finding arrays. Any byte difference is a failure, including a timestamp field that leaked into a finding. There is no skip list. Do not edit a fixture to hide a Node-specific bug; park the phase on that bug (S3).

Depends on: the CI matrix. Not packed.

Build:
1. Run both versions.
2. Diff sorted finding JSON.
3. Fail on any difference.

Acceptance: current fixtures match. A planted difference in a test double fails the diff. The diff script contains no skip list. The test asserts that.

FP risk: allowing a "known delta" file later. This phase does not add one. The report says a future delta file would be a different phase and an R1 decision.

### Phase 480 — Determinism under scheduler noise [`FULLSHIELD_EXPERIMENTAL_DETSTRESS`]
Repeat the fixture scan three times with shuffled directory order and different `UV_THREADPOOL_SIZE` values. The finding JSON must match byte for byte. One difference fails the job. There is no retry-until-green loop.

Depends on: Q11. Not packed.

Build:
1. Shuffle read order from a seed.
2. Run three times.
3. Diff. Do not retry.

Acceptance: three runs match. A planted unordered map in a test double fails. The script source has no retry loop. The test reads the script and rejects `retry`.

FP risk: a timing bug that shows up only on CI. That is a failure. The phase does not classify it as flaky.

### Phase 481 — Unsoundness register [`FULLSHIELD_EXPERIMENTAL_UNSOUNDREG`]
Generate nothing speculative. Check that every kind in the 271 enum has a heading in `docs/unsoundness.md` and that every heading is a kind. The human writes the one-line reason. The checker does not invent reasons. The opening paragraph says exhaustion over-approximates in `sound` mode and does not drop facts silently. The doc does not say the engine is sound.

Depends on: 271. Not packed.

Build:
1. Compare the enum to the headings.
2. Fail on drift.
3. Assert the opening sentence.

Acceptance: every current kind has a heading. A scratch kind without a heading fails. The opening sentence is present. The checker does not rewrite a human's reason paragraph.

FP risk: a reason that overclaims. The checker cannot judge prose. The human review is the control, and the doc's front matter stays `reviewed: false` until a person changes it.

### Phase 482 — Rule checklist [`FULLSHIELD_EXPERIMENTAL_RULECHECK`]
For each rule, record whether it has a positive fixture, a negative fixture, a Q10 mutant, a precision floor or the word `ungated`, and an FP paragraph. The result is a checklist. There is no numeric score and the JSON has no `score` field. Missing items fail `quality` only for rules added after this phase. Older rules are listed and follow the 94 ratchet: they do not fail the baseline. The checklist is not a review, and the report sentence says so.

Depends on: 94, 265. Not packed.

Build:
1. Check the five items.
2. Fail on new rules only.
3. Ban a `score` field.

Acceptance: a new rule missing a negative fixture fails quality. An old rule missing one is listed and does not fail. The JSON has `missing` and no `score`. The report sentence is in the script's stdout and the test asserts it.

FP risk: a new rule that checks every box and is still wrong. The sentence is the control. The phase does not relax Q10.

### Phase 483 — Flag ablation [`FULLSHIELD_EXPERIMENTAL_ABLATION`]
Run the bench apps with each named engine flag toggled off once, and write the finding-count delta. Set `unreviewed: true`. Do not pick a winner, do not change product defaults, and do not include holdout paths. The word `winner` must not appear in the output.

Depends on: the Section 49 flags under test. Not packed.

Build:
1. Run the toggles on the tuning and fixture repos the script is given.
2. Write counts.
3. Leave defaults untouched.

Acceptance: one row per toggled flag, with a count, on a tiny fixture repo. The output contains `unreviewed` and does not contain `winner`. Holdout names are not in the path arguments. Defaults in the code are unchanged.

FP risk: a count cited as quality. The bit is the control. The test asserts `unreviewed: true`.

### Phase 484 — Anti-overfitting check [`FULLSHIELD_EXPERIMENTAL_ANTIOVERFIT`]
Fail a branch when the diff changes a rule matcher and a tuning-app file under `bench/` and does not also change a handwritten fixture under `test/fixtures/`. Fail if the commit adds a results file for an `untouched` holdout. Fail if a new fixture's bytes equal a file under the tuning app (B8). The check judges the commit shape, not whether the rule is correct.

Depends on: B2, B3, B8. Not packed.

Build:
1. Inspect the diff.
2. Require a fixture beside a tuning-app change.
3. Forbid untouched results and byte-identical copies.

Acceptance: a rule edit plus a NodeGoat edit without a fixture fails. The same diff plus a handwritten fixture passes. A new untouched results file fails. A fixture that copies tuning-app bytes fails.

FP risk: a legitimate expected-output update. It still needs a fixture. The failure message says that.

### Phase 485 — Reproduction command check [`FULLSHIELD_EXPERIMENTAL_REPROKIT`]
If BENCHMARK.md contains a fenced reproduction block, run only commands whose program is `node`, `npm`, or `fullshield`, then diff the printed numbers to the file. Do not write the file. A mismatch exits 1. No block: exit 0 and print `no reproduction block`. Refuse `curl` and refuse any argument that is an `untouched` holdout name. Do not invent numbers to put in the block (R6).

Depends on: R6, R7. Not packed.

Build:
1. Parse the block.
2. Allowlist the programs.
3. Diff without writing.

Acceptance: a matching fixture block exits 0. A wrong number exits 1. `curl` is refused and not executed. An untouched holdout argument is refused. A missing block prints the sentence.

FP risk: a command that scans a holdout under another name. The holdout path check uses the registry's repo field and the directory name. The test uses the directory name and expects a refusal.

### Phase 486 — Local false-positive note [`FULLSHIELD_EXPERIMENTAL_FEEDBACK`]
`fullshield feedback fp <fingerprint>` appends to `.fullshield/feedback.json` the fingerprint, the witness locations, and the user's note. It does not send the file. The init template gitignores that path. An unknown fingerprint exits `FS-E` and creates no file. The command does not copy the source line's full text beyond the witness fields already stored. If 332 matches the note, the command warns locally and still writes, because the file is gitignored. The command constructs no HTTP client.

Depends on: 262, 340. Flag off: the command exits `FS-E`.

Build:
1. Append the local record.
2. Gitignore the path in the init template.
3. Warn on a 332 match in the note. Do not upload.

Acceptance: the file contains the fingerprint and the note. The fixture source line is not copied wholesale. No socket is opened. An unknown fingerprint creates no file. The gitignore line exists in the template.

FP risk: a note that holds a secret. The warning and the gitignore are the controls. The test puts a synthetic token in the note and expects the warning text and the file still local.

### Phase 487 — Candidate fixture from a note [`FULLSHIELD_EXPERIMENTAL_FIXPIPE`]
Turn one local feedback record into `test/fixtures/candidates/<id>/` with `reviewed: false` only when the witness already lives under `test/fixtures/`. If the witness points at a bench or tuning app, write a TODO file and do not copy that source (B8). The default runner does not load `candidates/`. The script does not set `reviewed: true` and does not network.

Depends on: 486, B8. Not packed.

Build:
1. Read the local feedback file.
2. Write a candidate or a TODO.
3. Leave the default runner's include list unchanged.

Acceptance: a record inside `test/fixtures` produces a candidate the default runner does not load. A record that points at a tuning app produces a TODO and not that app's source. `reviewed` is false. No network.

FP risk: a candidate becoming a regression test by accident. The runner include-list test excludes `candidates/`.

### Phase 488 — Human false-positive corpus [`FULLSHIELD_EXPERIMENTAL_FPCORPUS`]
`quality/false-positives.json` lists fingerprints a human marked `falsePositive`, each with a reason. If a scan of the corpus fixtures emits a listed fingerprint, CI fails unless the rule file names that fingerprint and why it changed. The implementation commit does not add rows (R3). A missing file prints `no false-positive corpus` and does not look like a pass in the README. An empty reason fails the schema. The human owns the marks (R1).

Depends on: 340. Not packed.

Build:
1. Load the file.
2. Fail on a reappearance without a rule-file note.
3. Do not add rows in the implementation commit.

Acceptance: a planted reappearance fails. The same reappearance with the note passes. An empty list prints the sentence. A temp copy is what the test edits. The committed JSON is not modified by the implementation.

FP risk: a true bug marked false. The required reason is the only schema control. The phase does not second-guess the mark.

### Phase 489 — Holdout rotation proposal [`FULLSHIELD_EXPERIMENTAL_HOLDOUTROT`]
Print which `seen` holdouts could leave the active set and which `untouched` reserves remain. Do not edit `bench/holdouts.json`. If fewer than two untouched reserves exist, exit 1 (B3). Do not scan the reserves. The script has no write call.

Depends on: B3. Not packed.

Build:
1. Read the registry.
2. Print the proposal.
3. Exit 1 below two reserves.

Acceptance: one reserve exits 1. Two reserves exit 0 and print the proposal. The registry hash is unchanged. No scan starts.

FP risk: a later edit path. The test asserts the hash and asserts the script source has no write of the registry.

### Phase 490 — Local evidence folder [`FULLSHIELD_EXPERIMENTAL_AUDITPACK`]
`fullshield evidence-pack <dir>` writes the scan JSON, the SBOM if it exists, the VEX if it exists, the unsoundness register, and the threat-model headings. The first line of the folder README says the contents are locally generated and are not a third-party assessment. A missing SBOM is named in the README and is not replaced by an empty SBOM. The scan JSON is required. Secrets are redacted (340). The command does not upload.

Depends on: 481. 496's headings are copied when that file exists. Flag off: the command exits `FS-E`.

Build:
1. Copy artifacts that exist.
2. Write the README's first line.
3. Refuse to invent a missing SBOM.

Acceptance: the folder contains the sentence and the scan JSON. A missing SBOM is named and no empty SBOM is written. The synthetic secret is absent. No network.

FP risk: the folder being sent as an attestation. The first-line sentence is the control. The test asserts it is line 1.

### Phase 491 — Release workflow provenance shape [`FULLSHIELD_EXPERIMENTAL_PROVSHAPE`]
Parse the publish workflow and check the provenance fields the file already claims: subject, build type, and the isolation the workflow text states. Read YAML only. Do not request a level from a service and do not add a badge. A missing field fails the checker. Do not insert a fake field to pass. If the real workflow is missing a field, park the phase and name the field (S3).

Depends on: the existing publish workflow. Not packed.

Build:
1. Parse the workflow.
2. Check the claimed fields.
3. Fail a fixture that deletes `subject`.

Acceptance: the deleted-subject fixture fails. The phase is done only if the real workflow passes or the report parks it with the field name. No network. The checker does not rewrite the workflow.

FP risk: a check that always passes. The deleted-field fixture is the guard against that.

### Phase 492 — Rebuild byte comparison [`FULLSHIELD_EXPERIMENTAL_REPROBUILD`]
Build the package twice on one OS and diff the tarball list and the JS hashes. Only files listed in human-owned `quality/repro-allow.json` may differ, and each row needs a reason. Two builds on one OS must match aside from that list. Do not rewrite the tarball inside the checker to hide a timestamp. If a timestamp is the difference, fix the build or add an allow row. The implementation commit may add the initial rows and must list them in the report. Later rows are R1.

Depends on: Q12. Not packed.

Build:
1. Build twice.
2. Diff.
3. Apply the allow list without rewriting bytes.

Acceptance: identical builds pass. A planted timestamp fails unless an allow row names the file. An allow row with an empty reason fails the schema. The checker does not rewrite the tarball.

FP risk: an allow list that eventually covers every file. Growth after the initial rows is human-owned. The report states that.

### Phase 493 — SBOM signature on the release [`FULLSHIELD_EXPERIMENTAL_RELEASESIGN`]
The release job runs 433's sign command with the CI secret. The spec does not create the secret and does not print it. A release job without the secret fails the workflow lint. A pull-request job without the secret does not fail. `continue-on-error` on the sign step fails the lint. The private key is not an artifact path. The test is a lint plus a dry run with a fixture key. There is no real publish.

Depends on: 433, 491. Not packed.

Build:
1. Point the release job at the sign command.
2. Lint the conditions above.
3. Dry-run with a fixture key.

Acceptance: the fixture workflow lints. The dry run writes a signature. A release job missing the secret fails the lint. A pull-request job missing it does not. `continue-on-error` fails the lint. No publish.

FP risk: a skipped sign step. The `continue-on-error` rejection is the control, and the test deletes that rejection and expects the lint to fail.

### Phase 494 — Hard-dependency guard [`FULLSHIELD_EXPERIMENTAL_DEPMIN`]
`dependencies` in `package.json` equals the committed allow list, which is empty. The test fails if a name is added. New peers must be optional (R13). Dev dependencies are Q4's problem. If a hard dependency already exists, park (S3) and do not delete it in this phase. The implementation commit does not modify `dependencies`. After this phase the allow list is human-owned, the same way 94's baseline is.

Depends on: R13, Q4. Not packed.

Build:
1. Assert the allow list.
2. Assert peers are optional.
3. Do not add a runtime dependency.

Acceptance: the empty list matches `package.json`. A scratch `leftpad` dependency fails. A peer without `optional: true` fails. The commit does not change `dependencies`.

FP risk: a later phase editing the allow list and the dependency together. The report says later edits are R1.

### Phase 495 — Workers under the permission model [`FULLSHIELD_EXPERIMENTAL_PERMWORKERS`]
Spawn scan workers with `node --permission` when the running Node supports it. Allow the repo path and the cache path. Do not allow child-process spawn in the default set. Network is limited to the hosts R15 already names, and only on a run the user asked to make networked. A worker read of `/etc/passwd` must fail. If Node 22 cannot express one needed permission, a reason row may name a single-capability fallback, and that fallback is logged. This phase adds no such row. Scanned code is still not executed.

Depends on: R15. Flag off: workers spawn as they do today.

Build:
1. Add the permission flags to the worker spawn.
2. Test an outside read fails.
3. Log any fallback. Add none in this commit.

Acceptance: a worker reads a fixture inside the repo. A read of `/etc/passwd` fails. `--allow-child-process` is absent. The R15 no-execute test still passes. No fallback row is added.

FP risk: a silent widen. A fallback without a reason fails the schema. The test asserts the default argument list.

### Phase 496 — Threat model document [`FULLSHIELD_EXPERIMENTAL_THREATDOC`]
Write `docs/threat-model.md` with the assets (source under scan, secrets in reports, the OSV cache, the runtime hook), the trust boundary (the repo is untrusted and is not executed, the network is the R15 host list), and each Section 31 rejection. A test fails if a Section 31 bullet's opening phrase is missing. Each in-scope threat links to a phase or to the words `not covered`. The doc contains none of the marketing phrases Section 31 bans. Front matter `reviewed` stays false.

Depends on: Section 31. Not packed.

Build:
1. Write the headings and the Section 31 list.
2. Link threats to phases or `not covered`.
3. Add the presence test.

Acceptance: every Section 31 opening phrase appears. A threat with no link and no `not covered` fails. The banned phrases are absent. `reviewed` is false.

FP risk: the doc drifting from Section 31. The phrase test is the control. It does not judge whether the prose is careful. That review is human, which is why `reviewed` stays false.

### Phase 497 — Local advisory drill [`FULLSHIELD_EXPERIMENTAL_DRILL`]
Copy a fixture OSV document into a temp cache, scan, and assert the advisory id is in the JSON and the SARIF validates, under a time budget. The id is a synthetic example the schema allows, not a real advisory the tool fetched. The script accepts no path to the production cache. It sends no mail and opens no socket. The package name lives in the temp fixture, not as a constant in the scanner, so renaming the package renames the finding.

Depends on: the OSV parser, 430. Not packed.

Build:
1. Use a temp cache.
2. Assert the id and the SARIF schema.
3. Write a local log.

Acceptance: the synthetic id appears. A broken SARIF fixture fails the drill. The production cache path is rejected as an argument. A renamed package still produces a finding for the new name. No network.

FP risk: a hard-coded id making the drill pass. The rename test is the control.

### Phase 498 — Release-build pins [`FULLSHIELD_EXPERIMENTAL_BUILDPIN`]
Lint the repo's workflows: Node and npm are pinned, actions use a SHA rather than a floating tag, and the install step is `npm ci --ignore-scripts`. This is FullShield's build, not the scanned project's start script (463). The lint fails; it does not rewrite. The implementation commit may add the pins, and the report lists every SHA for the human to verify before merge (R1). The tool does not claim it verified the SHAs.

Depends on: 491. Not packed.

Build:
1. Lint tags and the install command.
2. Pin floating actions in this commit if any remain.
3. List the SHAs in the report.

Acceptance: a fixture workflow with `actions/checkout@v4` and no SHA fails the lint. The repo workflows pass. `npm install` in a workflow fails the lint. There is no publish step in the test.

FP risk: a pin to a bad SHA. The listed SHAs and the human merge are the control. The phase text does not say the tool verified them.

### Phase 499 — Backport check [`FULLSHIELD_EXPERIMENTAL_BACKPORT`]
`docs/support.md` names the supported minor lines and says the human backports security fixes for stable rule ids. `scripts/backport-check.mjs` diffs finding keys `(ruleId, relative file, severity)` between this tree and a second checkout the human passes. A stable id that differs exits 1. An experimental-only difference exits 0. A missing path exits 0 and prints `no backport target`. The script contains no `git push`, `git merge`, or `npm publish`. Absolute paths are not part of the key.

Depends on: 447. Not packed.

Build:
1. Write the support doc.
2. Diff stable ids.
3. Leave the second tree untouched.

Acceptance: a stable-id difference exits 1. An experimental-only difference exits 0. A missing path prints the sentence. Two directories with different prefixes and the same relative finding match. The script source does not contain `npm publish` or `git push`.

FP risk: a path-only difference looking like a product change. The relative key is the control, and the two-prefix fixture locks it.

### Phase 500 — Stability contract for a future major [`FULLSHIELD_EXPERIMENTAL_STABILITY2`]
Add a section to `docs/stability.md` listing stable scan fields and stable rule ids, generated from rules whose front matter says `stability: stable` and from the schema's stable required keys. `semver-check` fails if a listed field or id disappears without a major bump. An id marked `deprecated` in minor N may be removed in N+2, and the checker enforces that window against changelog headings. Experimental keys under `experimental` may disappear in a minor. A rule without the stable bit stays off the list. This phase does not release 2.0, does not remove an id, and does not change default `scan --json`. The doc does not say the product is complete.

Depends on: R16a, 447. Not packed.

Build:
1. Write the section from the current stable set.
2. Enforce removal and the two-minor window in `semver-check`.
3. Leave the package version and the default JSON unchanged.

Acceptance: a scratch schema that drops a stable field fails the checker. A deprecation removed one minor later fails. A removal two minors later passes the checker and is not performed on this repo. The fixture `scan --json` matches the pre-phase snapshot. A rule without `stability: stable` is absent from the list.

FP risk: listing an experimental field as stable. The front-matter bit is the gate. The planted rule without the bit is the test.

---

## 50. Version 1.4.0

Target `1.4.0`, a minor (R16a): two new flags and one new error code. No new rule id. Default `scan --json` does not change. No R10. Nothing is promoted. `--repo` runs use local fixtures and do not park.

Order: 501, then 502. 502 does not import 501.

### Phase 501 — Diff scan frontier [`FULLSHIELD_EXPERIMENTAL_DIFFSCAN`]

Flag: `FULLSHIELD_EXPERIMENTAL_DIFFSCAN`. CLI: `--experimental-diffscan` sets the flag. `scan --diff` requires it.

`scan --diff` without the flag throws an error whose message contains `FULLSHIELD_EXPERIMENTAL_DIFFSCAN`. That error is `FS-E018`. `FS-E018` is matched before `FS-E006`, because the flag name contains the prefix `FULLSHIELD_EXPERIMENTAL_DIFF`.

With the flag and `--diff`:

1. The changed set is `git diff --name-only HEAD` (staged and unstaged tracked paths) plus `git ls-files --others --exclude-standard`. A git status other than 0 throws an error whose message contains `FULLSHIELD_EXPERIMENTAL_DIFFSCAN` and `git failed`. That is also `FS-E018`. The scan does not fall open onto the full tree.
2. A changed path is source when its extension is `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, or `.cts`. `.d.ts` is dropped. A changed non-source file adds no frontier file.
3. Hop cap is 1. The frontier is the changed source files, the walked source files that contain a relative string-literal import or `require` of a changed source file, and the walked source files that a changed source file imports or requires by a relative string literal. A file reached only on hop 2 is excluded.
4. A non-literal import is not an edge. Comment text is not an edge. A specifier that does not start with `.` is not an edge.
5. Resolution tries the literal, then the extensions in item 2, then `index` plus those extensions. The result must already be in the walked set. Symlinks are not followed.
6. SAST, secrets, config, and deps see only the frontier. Other files may be read as text to find relative import literals. They are not parsed with the TypeScript parser.
7. An empty changed set scans no source files. Exit is 0.
8. Carrier findings run only in this mode. A function in a changed file whose returned expression is request-tainted (`req.query`, `req.body`, `req.params`, `req.headers`, `req.files`, or a binding of those) is a carrier. An importer on the frontier that calls that function inside a sink argument reports the existing rule id. Sinks: `query` and `execute` are `SAST-SQLI-001`; `exec` and `execSync` are `SAST-CMDI-001`; `redirect` on `res` is `SAST-REDIRECT-001`; `eval` and `Function` are `SAST-EVAL-001`; `fetch` is `SAST-SSRF-001`; `readFile` and `readFileSync` are `SAST-PATH-001`; `find` and `findOne` are `SAST-NOSQLI-001`; `send` on `res` is `SAST-XSS-001` only when the argument text contains `<`. A function that returns a string literal is not a carrier.
9. Flag off, or `scan` without `--diff`: this module is not loaded. Default `scan --json` is unchanged. `clean-app` stays at 0 findings. No network. Scanned code is not executed. Two runs sort to the same `(ruleId, file, line, severity)` bytes.

Hop boundary: a sink in the direct importer fires. A sink that exists only in a file that imports that importer, and does not itself import the changed file, does not fire.

### Phase 502 — Field and closure taint [`FULLSHIELD_EXPERIMENTAL_FLOW2`]

Flag: `FULLSHIELD_EXPERIMENTAL_FLOW2`. CLI: `--experimental-flow2` sets the flag.

With the flag on, the existing injection rules also fire for two shapes the default taint pass drops. The module that implements the shapes loads only when the flag is `1`. Flag off, that module is not loaded and findings match the flag-off engine.

1. Field cap is 1. An assignment `obj.a = <tainted>` where `obj` and `a` are identifiers and the property is not computed stores the key `obj.a`. A later read of `obj.a` is tainted. A read of `obj.b` is not. A chain `obj.a.b` is not stored. A computed property `obj[key]` is not stored.
2. Closure cap is 1 function boundary. A name tainted inside a function is visible to a function nested directly inside it, unless the inner function declares that name or the object name of a field key. A sink two functions further in does not see the name.
3. `JSON.parse` and a bare `parse` do not clear the taint. A field stored from `JSON.parse(req.body.id)` still fires.
4. This phase does not flag Handlebars `{{ }}`, does not flag `res.json` of a tainted value as `SAST-XSS-001`, and does not flag a `url.includes` allowlist helper as `SAST-REDIRECT-001`.
5. Dynamic dispatch stays unreported. No new rule id. Severity and CWE stay the existing rule's values. The rules are `SAST-SQLI-001`, `SAST-NOSQLI-001`, `SAST-CMDI-001`, `SAST-PATH-001`, `SAST-SSRF-001`, `SAST-REDIRECT-001`, `SAST-XSS-001`, and `SAST-EVAL-001`.
6. No network. Scanned code is not executed. `clean-app` stays at 0 findings with the flag on. Default `scan --json` with the flag unset is unchanged on `vulnerable-app` and on the phase fixture. Two runs sort to the same bytes.

Field boundary: path length 1 fires. Path length 2 is silent. Closure boundary: depth 1 fires. Depth 2 is silent.

---

## 51. Version 1.5.0

Target `1.5.0`, a minor (R16a). Two behaviors that 1.4.0 kept behind a flag become the default scan. Two new checks stay off until their flag is `1`. No new hard dependency. No new error code. Scanned code is not executed. No new network host. `clean-app` stays at 0 findings with the new flags off and on. A `--repo` run uses local fixtures and does not park.

Order: 503, then 504, then 505, then 506. None of them import each other. 503 supersedes phase 502 item 6 for the default scan. 504 supersedes the phase 27 flag-off silence for the ORM and shell sinks named below. `FULLSHIELD_EXPERIMENTAL_DIFFSCAN` is unchanged from phase 501.

The human delegated the R3 edit on 2026-10-24: the phase 502 assertions that one field and one closure stay silent when `FULLSHIELD_EXPERIMENTAL_FLOW2` is unset, and the phase 27 assertions that Prisma `$queryRawUnsafe`, knex `raw`, `spawn` of `sh -c`, and zx `$.raw` stay silent without `FULLSHIELD_EXPERIMENTAL_SAST_GAPS`, are updated to expect those findings. No other existing test line changes.

### Phase 503 — Field and closure taint on the default scan

Flag: `FULLSHIELD_EXPERIMENTAL_FLOW2` stays accepted. CLI: `scan --experimental-flow2` still sets it. The flag does not turn this behavior off. R10 approved.

The shapes from phase 502 run when the flag is unset and when it is `1`.

1. Field cap is 1. Closure cap is 1 function boundary. A sibling field stays clean. Depth 2 and a chain `obj.a.b` stay silent. A shadowing declaration stays silent.
2. `JSON.parse` and a bare `parse` do not clear the taint.
3. No new rule id. Severity and CWE stay the existing rule's values. The rules are the eight named in phase 502.
4. This phase does not flag Handlebars `{{ }}`, does not flag `res.json` as `SAST-XSS-001`, and does not flag a `url.includes` allowlist helper.
5. No network. Scanned code is not executed. `clean-app` stays at 0 findings. Two runs sort to the same bytes.

### Phase 504 — ORM raw queries and shell variants on the default scan

Flag: `FULLSHIELD_EXPERIMENTAL_SAST_GAPS` stays accepted. CLI: `scan --experimental-sast-gaps` still sets it. The flag does not turn this behavior off. R10 approved.

The sinks that phase 27 gated run when the flag is unset and when it is `1`. No new rule id.

1. SQL sinks, still `SAST-SQLI-001` (high, CWE-89): `$queryRawUnsafe`, `$executeRawUnsafe`, `raw`, `literal`, `whereRaw`, `orderByRaw`, and `where` on a `createQueryBuilder` chain whose first argument is not an object. `whereRaw` and `orderByRaw` with a bindings array or object stay silent. A Prisma `$queryRaw` tagged template stays silent.
2. Command sinks, still `SAST-CMDI-001` (high, CWE-78): `` exec(`…${x}`) `` and the same for `execSync`, `spawn` or `spawnSync` of `sh`, `bash`, `zsh`, `dash`, `cmd`, `cmd.exe`, `powershell`, or `pwsh` with `-c` and a tainted next argument, `execa` with `shell: true`, and zx `$.raw`. `execFile` with an argument array stays silent. A default zx `$` tag stays silent.
3. Mongo `$where` strings stay as they are without this promotion.
4. No network. Scanned code is not executed. No package is installed. `clean-app` stays at 0 findings. Two runs sort to the same bytes.

### Phase 505 — LDAP injection [`FULLSHIELD_EXPERIMENTAL_LDAP`]

Flag: `FULLSHIELD_EXPERIMENTAL_LDAP`. CLI: `scan --experimental-ldap` sets the flag. Default is off. `stableChange: false`.

With the flag on, `search`, `compare`, `modify`, and `bind` report `SAST-LDAP-001` when the file imports a module whose specifier contains `ldap`, or the receiver identifier contains `ldap`, and the filter or the DN is request data. Request data is `req.query`, `req.body`, `req.params`, `req.headers`, or a binding of those. A property named `filter`, `dn`, `base`, or `baseDN` counts. A string-literal filter does not fire. Severity is high. CWE is CWE-90 (`https://cwe.mitre.org/data/definitions/90.html`). Confidence is high. Module is `sast`.

Flag off: this module is not loaded and default `scan --json` does not include `SAST-LDAP-001`. `clean-app` stays at 0 findings with the flag on. No network. Scanned code is not executed. Two runs sort to the same bytes.

### Phase 506 — Reflected CORS origin [`FULLSHIELD_EXPERIMENTAL_CORSREFLECT`]

Flag: `FULLSHIELD_EXPERIMENTAL_CORSREFLECT`. CLI: `scan --experimental-cors-reflect` sets the flag. Default is off. `stableChange: false`.

With the flag on, `CONFIG-CORS-002` fires when `Access-Control-Allow-Origin` is the request `Origin` header and credentials are allowed on that same response. The origin match is `req.headers.origin` or a binding of that member. Credentials means `credentials: true` on a `cors()` options object, or `Access-Control-Allow-Credentials` set to `true` or `'true'` in the same function. A fixed origin string does not fire. `origin: '*'` with credentials stays `CONFIG-CORS-001` and is not this rule. Severity is high. CWE is CWE-942 (`https://cwe.mitre.org/data/definitions/942.html`). Confidence is medium. Module is `config`.

Flag off: this module is not loaded and default `scan --json` does not include `CONFIG-CORS-002`. `clean-app` stays at 0 findings with the flag on. No network. Two runs sort to the same bytes.

## 51. Version 1.6.0

These phases are the approved `docs/FEATURES.md` for 1.6.0. A behavior that is not in that file is not in this section. No phase contacts a registry, opens a network connection, executes scanned code, or spawns a package, a shell, or an agent. `clean-app` stays at 0 findings with each flag off and on. Two runs sort to the same bytes. A `--repo` run does not park.

### Phase 507 — SQLite sinks on the SQL rule

Flag: none. `stableChange: true`. R10 approved. No new rule id.

`SAST-SQLI-001` also fires when the file mentions `node:sqlite`, `bun:sqlite`, or `DatabaseSync`, and request data is concatenated or interpolated into a member call `exec` or `prepare`. A member call whose object is `child_process` or `cp` does not fire. A string-literal query that uses `?` or a named placeholder, with the request value in a separate argument, does not fire because the query text is not tainted. `query` stays the existing stable sink. Severity, CWE, and confidence stay `SAST-SQLI-001`. The scanner does not open a database.

### Phase 508 — Bun and Deno shells on the command rule

Flag: none. `stableChange: true`. R10 approved. No new rule id.

`SAST-CMDI-001` also fires for `Bun.spawn` and `Bun.spawnSync`, including a `cmd` or `args` array, when the command or an argument is request data. It also fires for a tagged template `Bun.$`, and for a `$` template only when the file imports `bun`. It also fires for `new Deno.Command` when the command or an `args` entry is request data. A string-literal argument list does not fire. The scanner does not spawn a process. Severity, CWE, and confidence stay `SAST-CMDI-001`.

### Phase 509 — Library eval sinks

Flag: none. `stableChange: true`. R10 approved. No new rule id.

`SAST-EVAL-001` also fires for `evaluate` when the callee is a namespace, default, or `require` binding of `mathjs`, `expr-eval`, or `vm2`, or a named import `evaluate` from one of those three, or `new Parser().evaluate` when `Parser` comes from `expr-eval`. It also fires for `new VM` and `new NodeVM` when the file imports `vm2` and the code argument, or a `code` or `eval` option, is not a string literal. A string-literal argument does not fire. A function named `evaluate` that is not one of those three libraries does not fire. Existing `eval`, `new Function`, and `vm.runIn*` calls stay as they are. The scanner does not evaluate the argument. Severity, CWE, and confidence stay `SAST-EVAL-001`.

### Phase 510 — React Server Components versions [`FULLSHIELD_EXPERIMENTAL_RSC`]

Flag: `FULLSHIELD_EXPERIMENTAL_RSC`. CLI: `scan --experimental-rsc` sets the flag. Default is off. `stableChange: false`.

With the flag on, `DEPS-RSC-001` fires when `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, or `bun.lock` resolves `react-server-dom-webpack`, `react-server-dom-parcel`, or `react-server-dom-turbopack` to exactly `19.0.0`, `19.1.0`, `19.1.1`, or `19.2.0`. A prerelease such as `19.0.0-canary` does not fire. Any other version does not fire. A project with no lockfile does not fire. Severity is critical. CWE is CWE-502 (`https://cwe.mitre.org/data/definitions/502.html`). Confidence is high. Module is `deps`. The scanner does not contact a registry and does not install a package.

Flag off: this check is not loaded and default `scan --json` does not include `DEPS-RSC-001`.

### Phase 511 — Dependency release-age gate [`FULLSHIELD_EXPERIMENTAL_COOLDOWN`]

Flag: `FULLSHIELD_EXPERIMENTAL_COOLDOWN`. CLI: `scan --experimental-cooldown` sets the flag. Default is off. `stableChange: false`.

With the flag on, `CONFIG-COOLDOWN-001` fires when `.npmrc`, `pnpm-workspace.yaml`, `.yarnrc.yml`, or `bunfig.toml` is in the scan and its release-age gate is missing or shorter than three days. npm `min-release-age` is days. pnpm `minimumReleaseAge` is minutes (`4320` is three days). yarn `npmMinimalAgeGate` is a duration (`3d`, `72h`, `4320m`, or `259200s`). bun `minimumReleaseAge` is seconds (`259200` is three days). A value of `3` in the wrong unit fires, and the message names the unit. A gate of at least three days does not fire. A project that has only `package.json` and a lockfile, and none of those four files, does not fire. Severity is medium. CWE is CWE-829 (`https://cwe.mitre.org/data/definitions/829.html`). Confidence is medium. Module is `config`. The scanner does not install a package and does not contact a registry.

Flag off: this check is not loaded and default `scan --json` does not include `CONFIG-COOLDOWN-001`.

### Phase 512 — Import-time worm files [`FULLSHIELD_EXPERIMENTAL_IMPORTIMPLANT`]

Flag: `FULLSHIELD_EXPERIMENTAL_IMPORTIMPLANT`. CLI: `scan --experimental-import-implant` sets the flag. Default is off. `stableChange: false`.

With the flag on, `SUPPLY-IMPLANT-001` fires when a file already in the scan is named `setup_bun.js` or `bun_environment.js`, or a `package.json` `preinstall`, `install`, or `postinstall` script names either file. It also looks at `node_modules` on disk, which the default file walk skips, and stops after 2000 `package.json` files. It does not read the npm cache. A package whose files are not on disk is skipped. Symlinks are not followed. Severity is high. CWE is CWE-506 (`https://cwe.mitre.org/data/definitions/506.html`). Confidence is high. Module is `deps`. The scanner does not fetch a tarball, does not install a package, and does not execute a script.

Flag off: this check is not loaded and default `scan --json` does not include `SUPPLY-IMPLANT-001`.

### Phase 513 — Inflated dependency versions [`FULLSHIELD_EXPERIMENTAL_VERINFLATE`]

Flag: `FULLSHIELD_EXPERIMENTAL_VERINFLATE`. CLI: `scan --experimental-ver-inflate` sets the flag. Default is off. `stableChange: false`.

With the flag on, `DEPS-VERINFLATE-001` fires when a lockfile already in the tree contains a version whose major is `9999` or greater, or whose patch is `999` or `9999`. The version token is `major.minor.patch` and is not followed by a prerelease mark. `1.2.3` does not fire. Severity is high. CWE is CWE-427 (`https://cwe.mitre.org/data/definitions/427.html`). Confidence is high. Module is `deps`. The scanner does not contact a registry.

Flag off: this check is not loaded and default `scan --json` does not include `DEPS-VERINFLATE-001`.

### Phase 514 — Agent instruction files [`FULLSHIELD_EXPERIMENTAL_AGENTRULES`]

Flag: `FULLSHIELD_EXPERIMENTAL_AGENTRULES`. CLI: `scan --experimental-agent-rules` sets the flag. Default is off. `stableChange: false`.

With the flag on, the scan reads `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, files under `.cursor/rules/` and `.windsurf/rules/`, and `SKILL.md` under `.cursor/`, `.claude/`, or `.agents/`. `AGENT-UNICODE-001` fires on U+E0001–U+E007F, a zero-width character (U+200B, U+200C, U+200D, U+FEFF, U+2060), or a bidi override (U+202A–U+202E, U+2066–U+2069). `AGENT-INJECT-001` fires on `ignore previous` or `do not tell the user`. `AGENT-EXFIL-001` fires when the file contains an `http://` or `https://` URL and `.env`, `token`, or `secret`. `AGENT-SHELL-001` fires when the file names `claude`, `codex`, or `gemini` together with `--dangerously-skip-permissions`, `--permission-mode bypassPermissions`, or `--yolo`. A short guideline with none of those does not fire. Severity is high. CWE is CWE-74 for the first, second, and fourth, and CWE-200 for exfil (`https://cwe.mitre.org/data/definitions/74.html`, `https://cwe.mitre.org/data/definitions/200.html`). Confidence is high. Module is `config`. The scanner does not follow the instructions and does not fetch a URL.

Flag off: this check is not loaded and default `scan --json` does not include `AGENT-UNICODE-001`, `AGENT-INJECT-001`, `AGENT-EXFIL-001`, or `AGENT-SHELL-001`.

### Phase 515 — Coding-agent bypass spawn [`FULLSHIELD_EXPERIMENTAL_AGENTSPAWN`]

Flag: `FULLSHIELD_EXPERIMENTAL_AGENTSPAWN`. CLI: `scan --experimental-agent-spawn` sets the flag. Default is off. `stableChange: false`.

With the flag on, `SAST-AGENTSPAWN-001` fires when `exec`, `execSync`, `spawn`, `spawnSync`, `Bun.spawn`, `Bun.spawnSync`, or `new Deno.Command` launches `claude`, `codex`, or `gemini` with `--dangerously-skip-permissions`, `--permission-mode bypassPermissions`, or `--yolo` in that same call. Launching one of those programs without that flag does not fire. Severity is high. CWE is CWE-78 (`https://cwe.mitre.org/data/definitions/78.html`). Confidence is high. Module is `sast`. The scanner does not spawn the process.

Flag off: this check is not loaded and default `scan --json` does not include `SAST-AGENTSPAWN-001`.

### Phase 516 — MCP metadata attacks [`FULLSHIELD_EXPERIMENTAL_MCPPOISON`]

Flag: `FULLSHIELD_EXPERIMENTAL_MCPPOISON`. CLI: `scan --experimental-mcp-poison` sets the flag. Default is off. `stableChange: false`.

With the flag on, a JSON file that contains `mcpServers` gains three rules. `MCP-006` fires when a tool description or schema asks for a password, token, secret, or API key. `MCP-007` fires when a schema `default` string contains `ignore previous` or a shell marker (`` ` ``, `$(`, `&&`, or `|`). `MCP-008` fires when two servers in that file declare the same tool name. One server with a literal description does not fire. `MCP-001`–`MCP-005` stay on `FULLSHIELD_EXPERIMENTAL_MCPCFG`. Severity is high for `MCP-006` and `MCP-007`, and medium for `MCP-008`. CWE is CWE-74 for the first two and CWE-290 for the third (`https://cwe.mitre.org/data/definitions/290.html`). Confidence is high for the first two and medium for the third. Module is `config`. The scanner does not connect to a server.

Flag off: this check is not loaded and default `scan --json` does not include `MCP-006`, `MCP-007`, or `MCP-008`.

### Phase 517 — Vite filesystem exposure [`FULLSHIELD_EXPERIMENTAL_VITEFS`]

Flag: `FULLSHIELD_EXPERIMENTAL_VITEFS`. CLI: `scan --experimental-vite-fs` sets the flag. Default is off. `stableChange: false`.

With the flag on, `CONFIG-VITEFS-001` fires when `vite.config.js`, `vite.config.ts`, `vite.config.mjs`, `vite.config.cjs`, or `vite.config.mts` sets `server.fs.strict` to false, or sets `server.fs.allow` to `/` or a drive root. A config that leaves `server.fs` unset does not fire. Severity is high. CWE is CWE-22 (`https://cwe.mitre.org/data/definitions/22.html`). Confidence is high. Module is `config`. The scanner does not start Vite and does not contact a registry.

Flag off: this check is not loaded and default `scan --json` does not include `CONFIG-VITEFS-001`.

### Phase 518 — Host-header links [`FULLSHIELD_EXPERIMENTAL_HOSTPOISON`]

Flag: `FULLSHIELD_EXPERIMENTAL_HOSTPOISON`. CLI: `scan --experimental-host-poison` sets the flag. Default is off. `stableChange: false`.

With the flag on, `SAST-HOST-001` fires when `req.headers.host`, `req.headers['x-forwarded-host']`, `req.get('host')`, or `req.get('x-forwarded-host')`, or a binding of that value, is placed in an absolute URL (`http://`, `https://`, or `://`) that is passed to `redirect`, `location`, `sendMail`, or a `Location` header. A fixed host string does not fire. `req.hostname` by itself does not fire. Severity is high. CWE is CWE-644 (`https://cwe.mitre.org/data/definitions/644.html`). Confidence is high. Module is `sast`. The scanner does not send mail and does not open a connection.

Flag off: this check is not loaded and default `scan --json` does not include `SAST-HOST-001`.

### Phase 519 — Markdown HTML sinks [`FULLSHIELD_EXPERIMENTAL_MARKUP`]

Flag: `FULLSHIELD_EXPERIMENTAL_MARKUP`. CLI: `scan --experimental-markup` sets the flag. Default is off. `stableChange: false`.

With the flag on, `SAST-MARKUP-001` fires when `markdown-it` or `MarkdownIt` is constructed with `html: true` and `render` is called with request data, or when `marked` or `marked.parse` is called with request data. Request data is `req.query`, `req.body`, `req.params`, `req.headers`, or a binding of those. A string-literal markdown body does not fire. The file must import `markdown-it` or `marked`. Severity is high. CWE is CWE-79 (`https://cwe.mitre.org/data/definitions/79.html`). Confidence is high. Module is `sast`. The scanner does not render the markdown.

Flag off: this check is not loaded and default `scan --json` does not include `SAST-MARKUP-001`.

### Phase 520 — Auth.js trustHost [`FULLSHIELD_EXPERIMENTAL_TRUSTHOST`]

Flag: `FULLSHIELD_EXPERIMENTAL_TRUSTHOST`. CLI: `scan --experimental-trust-host` sets the flag. Default is off. `stableChange: false`.

With the flag on, `SAST-TRUSTHOST-001` fires when a file that mentions `next-auth`, `@auth/`, or `NextAuth` sets `trustHost` to `true`. `trustHost: false`, or a config that omits `trustHost`, does not fire. Severity is medium. CWE is CWE-346 (`https://cwe.mitre.org/data/definitions/346.html`). Confidence is medium. Module is `sast`. The scanner does not perform a login.

Flag off: this check is not loaded and default `scan --json` does not include `SAST-TRUSTHOST-001`.
