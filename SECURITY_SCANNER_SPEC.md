# FullShield — Build Spec for Cursor (full, rev 2026-10-19e)

> Package: `fullshield` on npm (owner `kathan2404`). Repo: https://github.com/kathanp/fullshield (public, MIT).
> Language: TypeScript (strict). Runtime: Node.js ≥ 22.13. Distribution: one npm package (CLI + library + runtime middleware).
> Live on npm: `0.1.0`, `0.1.1` (both with provenance), `0.1.3` (**published WITHOUT provenance — must never happen again**). Placeholders `0.0.0-stage`, `0.0.1` deprecated. `0.1.2` was never published.
> This file is the only spec. The 2026-10-14 draft (`SECURITY_SCANNER_SPEC (1).md`) is deleted. Its design lives here; Section 33 lists the few requirements that draft stated and this file had shortened. Later text wins where the draft disagreed.
> [X] Complete: phases 1–49, 53–55, 57–64, 66–74. Phase 65 is coded; the 5-second nest/undici target is still unmet. Phases 50, 51, 52, and 75 have fixture tests and still need a bench snapshot diff before merge (R10). Skip Phase 56 until R15 is amended. Experimental phases stay off unless their flag is set. Phases 36–45 are reference, not a queue.
> **Current queue is Section 43 (Finish-All Run)**; Section 42 adds the quality gate (R24, Phase 94) and the definition of done for every remaining phase. Section 40.5 report-file rules still apply. Earlier queue: Section 40 (2026-10-19, lanes A/B/C). Section 36 is the 2026-10-18 record. Leadership phases 76–93 are in Section 39. Advanced phases 60–75 are in Section 37; Phase 47 has an addendum (47.1) there that is part of its acceptance. Section 38 is the production-reliance stance (not a queue). Section 41 lists human-only work. Phases 76–93 are not started.

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
Taint: sources `req.body/query/params/headers/cookies`, destructured request params, `process.argv` (+ framework sources behind flags). Propagation: assignment, concat, template literals, method-call receivers, function params and returns (same file and cross-file via `require`/`import`, depth 5). A value returned from a helper in another file is still missed until Phase 51. Sanitizers are sink-specific: parameterized query APIs (SQL), zod/joi/yup `.parse` result only, `validator.*` only for the check that function actually performs, `path.resolve` + `startsWith(base)` (path), `encodeURIComponent` (URL/redirect only), HTML escape/DOMPurify (XSS only). `JSON.parse`/generic `parse` never clear taint. A schema that only checks "this is a string" does not clear SQL concatenation. Parameterized queries are never flagged. Phase 53 may add class-validator on the same rule: the schema clears a finding only for the class that schema constrains.

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
- [ X ] Tarball: `dist/` (no `.map`), README, LICENSE, CHANGELOG, templates, rules. Budget: unpacked ≤ 2.0 MB, ≤ 120 files (Phase 36).
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
- [  ] Public alpha (0.x); APIs may change.
- [  ] Phase 87 provenance signals are informational (`SUPPLY-PROV-001`, medium). They never mean a package is malicious. Offline or cache-miss data stays unknown.
- [ X ] The package enforces Node ≥ 22.13 in `engines`, `doctor`, and CI (Node 22 and 24). Node 20 reached end of life in April 2026. The README says 0.4.0 and does not claim a reviewed recall number. History storage may still say it needs `node:sqlite`. That API is inside the floor. Branch protection job names are a human GitHub setting after the new jobs report once.
- [  ] Ground truth is unreviewed (`"reviewed": false` on every bench app). Cursor does not flip that flag. A human reviews answer keys. Blank label, reviewer, and note cells stay blank.
- [ X ] Default console prints the Phase 47 shown rows only (human decision 2026-10-18). JSON stays the full list. D4 accepts the 2026-10-18 grouped-row recount: NodeGoat 36, goof 63, juice-shop 49, dvna 14, vulnerable-node 41. There is no row-count threshold. Ground truth stays unreviewed.
- [  ] Platforms: Linux, macOS, Windows on Node ≥ 22.13.
- [  ] Benchmark recall figures are on **unreviewed** ground truth; tuning-app figures are `seen` (rules were fixed against them). Current untouched-app figure: none (all apps used). Do not cite a recall percentage until Phase 37 + review.
- [  ] RASP corpus results are on self-authored/vendored corpora.
- [  ] NoSQL: a filter object or array built from request input and passed into find/update is reported, including a helper in the same file and a nested function that closes over the filter. A filter returned from another file is still missed (Phase 51).
- [  ] Template engines: Swig `{{ }}` in `.html` is still missed. Phase 50 flags that pattern only after the app sets a raw engine such as Swig. Handlebars `{{ }}` stays unflagged. JSON-context XSS, `url.includes` allowlist bypass, and the DVNA calc vs `err.stack` pattern stay missed.
- [  ] Reachability is import-level + any-call; symbol-level only after Phase 39.
- [  ] All features from Phase 27 onward, RASP, AI, and Frontier are experimental.
- [  ] Capability profiles (Phase 86, `FULLSHIELD_EXPERIMENTAL_CAPABILITIES`) read installed files only and do not run install scripts. `deps-diff` reports a new capability only when the previous integrity is already cached. Files over 1 MB are skipped. Comments and strings that mention an API can match.
- [  ] FullShield does not stop attacks by itself: `--fail-on` and runtime monitor/block are the prevention mechanisms.
- [  ] No deterministic detection of business-logic or authorization bugs.
- [  ] Production reliance is Section 38. README and release notes keep that stance. Do not claim FullShield replaces Semgrep, npm audit, OSV-Scanner, or a secrets scanner.
- [  ] `ingest` (Phase 83) reads local report files only. It does not run Semgrep, npm audit, or OSV-Scanner and does not fetch. It does not set `fullshieldPriority` (Phase 84; KEV/EPSS stay blocked on Phase 56). An npm audit file with no installed version uses `unknown` and will not match an OSV-Scanner row that has a version.
- [  ] Phase 91 fix verification re-scans the patched file and its direct importers only. A missing OSV cache file for the planned version is `does-not-remove`. It does not run project tests or `npm install`.

---

## 29. Depth Phases 36–45 (SHIPPED in 0.2.0 — reference)

Do not rebuild these. `0.3.0` grouped duplicate finding keys. `0.4.0` reports a Mongo filter built in the same function. Neither version is a reason to reopen 36–45. The next work is Section 36, which orders Section 32 and Section 37.

### [X] Phase 36 — Release integrity (BLOCKS ALL RELEASES)
Build:
1. Provenance gate in `publish.yml` (1.4). Root-cause 0.1.3's missing attestation; document in RELEASING.md.
2. `scripts/default-scan-diff.mjs`: snapshots default-scan findings per target into `bench/snapshots/<version>.json`; diff mode prints added/removed/changed `(ruleId, file, line, severity)`; exit 1 on any diff unless `--approved <file>` matches exactly. Create snapshots for 0.1.1 and 0.1.3 from their published tarballs (`npm pack fullshield@X` into temp, run that CLI).
3. `scripts/semver-check.mjs`: HEAD vs last tag — new rule IDs, commands, flags, exports, or stable-output diff → minor required; else patch. Fails if the `package.json` bump is smaller than required.
4. `scripts/pack-budget.mjs`: fails if unpacked > 2.0 MB, files > 120, or hard `dependencies` added vs last tag; prints what grew.
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
| Repo `package.json` | 0.4.0. The human set this release on 2026-10-18. README says 0.4.0. |
| `engines` | `>=22.13` in package.json, doctor, and CI (Node 22 and 24). Not pushed. Branch protection still needs a human after the new jobs report. |
| Built | phases 1–46 in this working tree. Phase 47 console implements D3. D4 accepts the grouped-row table and removes the 40-row stop. Nothing pushed. |
| Today's queue | Section 40 (2026-10-19): Lane A 75/50/51/52 diffs → 78 → 65 re-measure; Lane B 76, 77, 92, 93; Lane C 82, 81, 80, 84, 83, 86, 87, 85, 79, 88, 91, 89, 90. Section 36 (2026-10-18) is the record: 46–49, 53–55, 57–64, 66–74 done. |
| Phases 76–93 | specified 2026-10-19, not started |
| Precision | not measured; Phase 76 builds the sampler, labels are human-only |
| Phase 56 | blocked on R15 amendment (EPSS/KEV hosts) |
| Ground truth reviewed | none (all `reviewed: false`). Human only |
| Untouched holdouts in reserve | 3 (verademo-javascript, serverless-goat, mongection), not scanned |
| Provenance gate | in publish.yml. `0.1.3` was published without provenance and must not be repeated |
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

Phases 1–6 in `docs/STABILIZATION-PLAN.md` are already in `0.3.0`: `docs/NOISE-REPORT.md`, dependency grouping, SAST sink-line dedupe, default excludes, `SAST-SKIP-001`, streaming parse, `bench/review/*.csv` with blank labels, Node 20, and `COMPARISON.md` plus `bench/class-map.json`. Those counts are unreviewed. They are not a precision or recall claim. Node 20 support is removed by Phase 46.

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

2. [  ] **npm audit and OSV-Scanner stay the mature dependency databases.** FullShield queries OSV (`https://api.osv.dev`) and can read `npm audit --json` (R6). It does not replace either tool. Reachability is a layer on top of those alerts, not a second advisory database.

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
- [  ] `docs/QUALITY.md`: one page listing Q1–Q12, what each enforces, and today's numbers. Linked from README.
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

**R25. One queue only.** This section is the only work queue. `docs/RUN-PROMPT.md`, `PROGRESS.md`, `docs/RUN-LOG.md`, `.cursor/rules/*`, `AGENTS.md`, and any other file may record history but may not define a queue, batches, or a stop point. Any batch list or "stop after this batch" text in those files is void. At Stage 0, replace the body of `docs/RUN-PROMPT.md` with one line: `Superseded. The only queue is SECURITY_SCANNER_SPEC.md Section 43.` and remove any stop/batch instructions from `.cursor/rules/*` and `AGENTS.md` if present (commit `docs: retire old run prompt (R25)`). Phases already marked [X] in this spec are never redone.

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
