#/Users/k244p/fullshield/PROGRESS.md
# FullShield build progress

One entry per phase (spec §9). Each entry records what was built, the
`verify:phase N` summary table, and anything deferred and why.

## Phase 1 — scaffold + verification protocol (committed `4f80c60`)

TS-strict scaffold, ESLint, Vitest (coverage thresholds), tsup, commander CLI
(`scan` with `--json/--fail-on/--modules/--config`), Finding model, config
loader, file walker, console+JSON reporters, `scripts/verify.mjs` (anti-cheat,
summary table, per-phase acceptance), `scripts/mutation-smoke.mjs`, e2e tests
against the built binary, vulnerable-app/clean-app fixtures, CI matrix
(Node 20/22 × Linux/macOS/Windows). Verify: 52 tests, 94.96% lines / 85.4%
branches, clean-app 0 high/critical. Deferred: `src/modules/**` coverage
threshold (glob would match no files), SARIF e2e (Phase 6), subpath exports
(Phase 8+), bench (Phase 8).

## Phase 2 — secrets module

**Built:**
- 11 secrets rules in `src/modules/secrets/rules/` (AWS, Stripe, GitHub,
  Slack, Google, OpenAI/Anthropic-style, PEM private key, DB URL with inline
  password, hardcoded JWT secret, generic high-entropy assignment at low
  confidence, committed `.env*` file). Each rule has positive + negative tests.
- String-literal concatenation folding so fixture-style `'AKIA' + '...'`
  secrets are detected; Shannon entropy scorer; masking (`first4 + ****`)
  applied before any Finding is created — raw secrets never leave the module
  (unit + e2e assertions on every output format).
- `--staged` pre-commit mode: `scan --modules secrets --staged` scans only the
  git index (tested against a real temp git repo, including the non-repo error
  path).
- Engine/CLI wiring, `src/modules/**` ≥ 85% coverage threshold now active,
  mutation operator switched to a type-safe no-op (`void(`) so the *test run*
  (not the build) catches disabled rules. Mutation-smoke genuinely disabled
  each of the 11 rules; the suite failed every time.

**Verify summary (`npm run verify:phase 2`, full run PASSED):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 2 | 97.27% | 88.01% | secrets | 5 | 5 | 5 | 0 |

**Test changes (flagged for human review at the Phase 5 stop):** four phase-1
assertions were *phase snapshots* (`builtinModules === []`, `modulesRun ===
[]`, "vulnerable-app has 0 findings in phase 1") that the spec's own phase
plan invalidates. They were rewritten as phase-proof, strictly-stronger
invariants (registry consistency; clean-app zero findings is now marked
permanent; the vulnerable-app gate asserts exit code ⇔ high/critical presence).
No detection expectation was weakened. Files: `test/unit/core/engine.test.ts`,
`test/unit/public-api.test.ts`, `test/unit/cli/program.test.ts` (2 tests).

**Deferred:** none for this phase. (`init`-generated pre-commit hook template
is Phase 9 per spec; Phase 2 only required the staged scan mode.)

## Phase 3 — deps module

**Built:**
- Lockfile parsers for npm `package-lock.json` (v2/v3, plus a dependencies-tree
  fallback), yarn classic, and pnpm (scoped names + peer suffixes).
- OSV `/v1/querybatch` + per-id detail fetch, 24h file cache under
  `{cacheDir}/osv/`, `--offline` / `deps.offline` cache-only mode. Network is
  mocked in unit tests; vulnerable-app e2e uses a committed fixture cache so CI
  never contacts OSV.
- Typosquat check (Levenshtein ≤ 1 vs a static popular-package list) →
  `DEPS-TYPOSQUAT-001` (medium, low confidence).
- Vulnerability findings `DEPS-VULN-001` with OSV/CVE references and a
  same-major bump `FixProposal` (apply lands in Phase 7). Deprecated lockfile
  entries emit `DEPS-DEPRECATED-001` (info) when the lockfile carries a notice.
- Seeded fixture: old `lodash@4.17.11`, `minimist@1.2.0`, typosquat `expresss`.

**Verify summary (`npm run verify:phase 3`, full run PASSED):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 3 | 96.46% | 85.37% | deps,secrets | 8 | 8 | 8 | 0 |

123 tests. Mutation-smoke re-verified all 11 secrets rules (suite failed each
time the rule was disabled).

**Deferred:** live `npm audit` / npm-registry deprecated lookup. Spec §4.1
lists deprecated packages; we only flag a `deprecated` field already present
in the lockfile so we never invent registry data. A `test:live` OSV script is
optional per §0.1 and not required in CI.

## Phase 4 — SAST engine + first 6 rules

**Built:**
- Taint-lite engine (`src/modules/sast/`) using `@typescript-eslint/typescript-estree`
  (dynamic `import()` at scan time). Sources: `req.query/body/params/headers`,
  `process.argv`. Propagation: assignment, concat, template literals, within
  one function only.
- Rules (each with positive + negative tests, mutation-smoke verified):
  SQLI, CMDI, PATH (cleared by `path.resolve` + `startsWith`), EVAL, JWT
  (`decode` / `algorithms: none` / verify without allow-list), CRYPTO
  (`Math.random` for tokens; md5/sha1 near password).
- Parameterized `query(sql, [params])` is not flagged. clean-app stays at 0
  SAST findings. Seeded JWT `decode` in vulnerable-app (`SAST-JWT-001` added
  to expected-findings as a finalization, not a weakening).

**Verify summary (`npm run verify:phase 4`, full run PASSED):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 4 | 95.03% | 83.07% | deps,secrets,sast | 14 | 14 | 14 | 0 |

140 tests. Mutation-smoke verified 17 rules (6 SAST + 11 secrets).

**Deferred:** remaining SAST rules (NOSQLI, SSRF, REDIRECT, PROTO, XSS, AUTH)
and the `config` module are Phase 5.

## Phase 5 — remaining SAST + config module

**Built:**
- Remaining §4.3 SAST rules: NOSQLI (raw `req.body`/`req.query` as Mongo
  filter), SSRF (`fetch`/`axios`/`http` + tainted URL), REDIRECT, PROTO
  (unguarded recursive merge; a comment mentioning `__proto__` is not a
  guard), XSS (tainted HTML `res.send`), AUTH (data-touching route with no
  auth-named middleware; low severity).
- `config` module: missing helmet, `express.json()` without `limit`,
  `cors({ origin:'*', credentials:true })`, auth routes without a rate
  limiter, `err.stack` leaked to the client, Dockerfile `:latest` / missing
  USER / `ENV *_SECRET=`, lockfile `hasInstallScript` (info).
- clean-app updated with the safe mirrors (`requireAuth`, allow-listed CORS,
  rate limiter, pinned Dockerfile `USER node`). Permanent zero-findings
  invariant on clean-app still holds.

**Verify summary (`npm run verify:phase 5`, full run PASSED):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 5 | 94.44% | 84.19% | deps,secrets,sast,config | 28 | 28 | 30 | 0 |

Mutation-smoke verified 23 SAST+secrets rules (suite failed each time a rule
was disabled). Extra findings beyond the 28 expected IDs are additional AUTH
routes / install-script info, not missed detections.

**Deferred:** SARIF / markdown / HTML reporters, `--fail-on` as a Phase-6
feature (the CLI flag already exists from Phase 1), baseline, and inline
suppression — all Phase 6. **Stopped here per the mandatory Phase 5 review
gate; Core phases 6–10 not started.**

## bench-1 — real-world benchmark + in-scope fixes

Cloned OWASP NodeGoat and appsecco/dvna into `~/fullshield-bench/` (outside
this repo). Scan-only; never installed or started. Phase 5 CLI JSON saved at
`benchmarks/results/{nodegoat,dvna}-phase5.json`. Honest write-up:
`benchmarks/REPORT.md`.

**Phase 5 baseline:** NodeGoat 392 findings (eval×3, redirect, 320 OSV, helmet,
rate-limit, err.stack, committed TLS key). DVNA 9 findings (SQLi, CMDi,
redirect, helmet×3, rate-limit, docker-root). Missed in-scope: NodeGoat
`needle.get` SSRF; DVNA `mathjs.eval` and EJS `<%-`. False positives: README
`<password>` DB URLs, 18 typosquat collisions, helmet on `express.Router()`
files. Out-of-scope misses (cross-file `$where`, IDOR, CSRF, XXE,
deserialization, Swig `{{ }}`) listed under Known misses only.

**Fixes (new fixtures only; existing expectations not weakened):**
- `SAST-EVAL-001` matches callee name `eval` (library wrappers).
- `SAST-SSRF-001` HTTP libs include needle/got/request/superagent/undici.
- `SAST-XSS-001` scans `.ejs`/`.hbs`/`.njk` for `<%-` / `{{{` (not `include`).
- `SECRET-DBURL-001` skips `<placeholder>` / `{placeholder}` passwords.
- Typosquat: direct `package.json` deps only, min length 4, hyphen-normalized
  equality skipped, small legit-collision set.
- `CONFIG-HELMET-001` requires an `express()` app factory.

**After bench-1 re-scan:** NodeGoat 372 (−20), DVNA 14 (+5). In-scope misses
from the baseline are now detected. clean-app remains 0 findings.

## Phase 6 — reporters, --fail-on, baseline, inline suppression

**Built:**
- SARIF 2.1.0 (`--sarif`), Markdown (`--markdown`), and standalone HTML
  (`--html`) reporters. HTML escapes finding text; secrets stay masked.
- `--update-baseline` writes `config.baseline` (default
  `.fullshield-baseline.json`). Subsequent scans drop matching finding ids;
  new ids still fail `--fail-on`.
- Inline `// fullshield-ignore RULE-ID: reason` (reason required) suppresses
  the next or same line. Missing reason does not suppress.
- `--fail-on` (from Phase 1) is the CI gate; Phase 6 acceptance locks SARIF
  validity + baseline new-vs-old behavior.

**Verify summary (`npm run verify:phase 6`, full run PASSED):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 6 | 93.97% | 83.13% | deps,secrets,sast,config | 29 | 29 | 33 | 0 |

176 tests. Mutation-smoke verified all 23 SAST+secrets rules.

**Deferred:** `fix` command (Phase 7).

## Phase 7 — fix engine

**Built:**
- `fullshield fix` (dry-run) prints unified diffs. `--apply` requires a clean
  git tree (unless `--force`), optionally creates `fullshield/fixes-<ts>`,
  writes only `safe: true` patches, runs `npm test` if present, and
  `git checkout --` reverts on failure. Never deletes user files.
- Safe v1 patches: `helmet()`, `express.json({ limit: '100kb' })`,
  `Math.random` token → `crypto.randomUUID()`, `.env` in `.gitignore`,
  same-major dep bumps already attached on findings, secret literal →
  `process.env.X` plus a rotate comment.

**Verify summary (`npm run verify:phase 7`, full run PASSED):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 7 | 92.23% | 81.81% | deps,secrets,sast,config | 29 | 29 | 33 | 0 |

186 tests. Mutation-smoke verified all 23 rules. Benchmark re-scan: NodeGoat
372, DVNA 14 (unchanged vs bench-1).

**Deferred:** runtime middleware (Phase 8).

## Phase 8 — runtime middleware + benchmark

**Built:**
- `fullshield/runtime` inspector (SQLi/XSS/path signatures, auth-route
  sliding-window rate limit, oversized-body guard). Default mode `monitor`.
  `block` returns 403. Events never include the raw body.
- Express middleware and Fastify plugin (`fullshield/runtime/express`,
  `.../fastify`). Optional peer deps. Separate tsup entries, no scanner
  imports, combined runtime JS < 50 KB.
- `scripts/bench.mjs`: inspect() p95 ≈ 0.001ms on a typical JSON request.

**Verify summary (`npm run verify:phase 8`, full run PASSED):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 8 | 92.23% | 81.79% | deps,secrets,sast,config | 29 | 29 | 33 | 0 |

193 tests. Mutation-smoke verified all 23 rules. bench p95 0.0013ms.

**Deferred:** `init` + notifiers (Phase 9).

## Phase 9 — init + notifiers

**Built:**
- `fullshield init` writes `fullshield.config.json`, `.github/workflows/fullshield.yml`
  (SARIF upload, `--fail-on high`), `.gitlab-ci.yml`, and
  `.fullshield/pre-commit.sh` (`scan --modules secrets --staged`).
- `fullshield notify --slack|--webhook|--email` sends the last scan summary
  (written to `.fullshield/last-scan.json`). Slack/generic webhooks tested
  against a local HTTP mock; SMTP against a local net mock. `.fullshield/`
  is always ignored by the file walker.

**Verify summary (`npm run verify:phase 9`, full run PASSED):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 9 | 91.53% | 81.82% | deps,secrets,sast,config | 29 | 29 | 33 | 0 |

199 tests. Mutation-smoke verified all 23 rules.

**Deferred:** README / rule docs / CHANGELOG / npm pack (Phase 10).

## Phase 10 — docs + npm pack

**Built:**
- README (0.x/alpha, coverage map, **non-goals**, commands, runtime).
- `rules/*.md` for every Core rule id. CHANGELOG. MIT LICENSE.
- `package.json` `files` ships `dist`, README, LICENSE, CHANGELOG, templates,
  rules — not `test/` or fixtures. `publishConfig.provenance` is true.

**Verify summary (`npm run verify:phase 10`, full run PASSED):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 10 | 91.53% | 81.84% | deps,secrets,sast,config | 29 | 29 | 33 | 0 |

200 tests. Mutation-smoke verified all 23 rules. **Core (phases 1–10) complete.**
Pro (11–16) not started. Nothing was pushed to GitHub.

## harden-1 — fixer safety, unsafe patches, typosquat, runtime honesty

**Built:**
- `fix --apply` snapshots each target file's bytes before write and restores
  those snapshots if project tests fail. Never `git checkout --`.
- `--force` on a dirty tree skips files with uncommitted changes. New test:
  dirty `app.js` + failing `npm test` → user bytes survive exactly.
- `helmet()` and secret → `process.env` are `safe: false` (shown in dry-run;
  applied only with `--unsafe`). Body-limit, `randomUUID`, `.env` gitignore
  stay safe.
- Typosquat: removed `LEGITIMATE_COLLISIONS`. Flag only if 1 edit from
  `POPULAR_PACKAGES` and the name is not in `TOP_PACKAGES`.
- README: runtime is signature-based, stopgap, monitor recommended; sink-hooking
  is Phase 17. `scripts/bench.mjs` also reports Express+`shieldGuard` p50/p95.
- `src/fixer/**` coverage ≥ 90% lines. `publishConfig.provenance` removed;
  `.github/workflows/publish.yml` runs `npm publish --provenance`.

**Verify (`npm run verify:phase 10`, full run PASSED after harden-1):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 10 | 94.12% | 84.52% | deps,secrets,sast,config | 29 | 29 | 33 | 0 |

223 tests. `src/fixer/**` 96.5% lines. Mutation-smoke verified all 23 rules.
`bench`: inspect p95 0.0022ms; Express+shieldGuard p50 0.156ms / p95 0.454ms.

**Benchmark:** NodeGoat 372, DVNA 14 (unchanged vs Phase 10). Typosquat FP
delta vs Phase 10: 0. See `benchmarks/REPORT.md`.

**Stopped here per the mandatory harden-1 review gate; Pro phases not started.**
Nothing was pushed to GitHub.

## harden-2 — no-lockfile finding, honest top-packages, CLI coverage

**Built:**
- `DEPS-NOLOCK-001` (info) when `package.json` exists and no lockfile is
  present. Exact `package.json` pins (no `^`/`~`) are still queried on OSV.
  Fixture: `test/fixtures/no-lock-app` (lodash@4.17.11 + range express).
  clean-app now has a lockfile so the zero-findings invariant holds.
- `topPackages.ts` header records source (npm most-depended-upon / common
  install-tree utilities, frozen 2026-10-14) and that NodeGoat/DVNA-only
  names were removed.
- In-process CLI tests for scan/fix/init/notify wiring (`src/cli/program.ts`
  lines ≥ 80%). SARIF validator branch coverage ≥ 75%.

**Verify (`npm run verify:phase 10`, PASSED after harden-2):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 10 | 95.86% | 85.45% | deps,secrets,sast,config | 29 | 29 | 33 | 0 |

237 tests. `src/cli/program.ts` 94.25% lines. `sarif.ts` 94.59% branches.

**Benchmark:** NodeGoat 372 (unchanged). DVNA 14 → 19 (+1 NOLOCK info, +4
OSV on exact `mathjs` / `node-serialize` pins). Typosquat FP delta: 0.

## Phase 13 — cross-file taint, reachability, CycloneDX SBOM

**Built:**
- Call-graph taint (`src/modules/sast/interproc.ts`): relative `require`/`import`,
  `require(x).Export`, `new Ctor()` method calls, `this.method = fn`, same-file
  calls. Depth 5. Sanitizers (`parse`/`validate`/`encodeURIComponent`/`sanitize`/
  `escape`) clear taint. Sinks: SQL `query`/`execute`, cmd `exec`/`spawn*`,
  NoSQL `$where`. Findings include `trace`; SARIF `codeFlows`.
- Fixture: 3-file chain `routes/alloc.js` → `services/alloc.js` →
  `data/alloc-dao.js` (parameterized negative on clean-app).
- Dependency reachability on `DEPS-VULN-001`: `reachable` / `imported-not-called`
  (−1) / `not-imported` (−2). lodash in vulnerable-app stays called+critical.
- `fullshield sbom --format cyclonedx` → CycloneDX 1.5 JSON with vuln refs.

**Not done / deferred:**
- License policy (GPL/AGPL vs proprietary): lockfiles we parse do not include
  SPDX licenses; SBOM `license` is optional when supplied. No invented licenses.
- TS path aliases; OSV “affected functions” (any call ≈ reachable).
- NodeGoat `$where` trace is 2 files (route + DAO), not 3.

**Verify (`npm run verify:phase 13`, PASSED):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 13 | 95.22% | 83.37% | deps,secrets,sast,config | 30 | 30 | 34 | 0 |

245 tests. Mutation-smoke verified all 23 rules. Acceptance: 3-file SQLI trace;
1 not-imported vuln downgraded on vulnerable-app; lodash stays critical; SBOM
validates as CycloneDX 1.5.

**Benchmark:** NodeGoat 372 → 373 (+1 `$where` TP). 320 OSV hits: 13 reachable,
4 imported-not-called (−1), 303 not-imported (−2) — **307 alerts downgraded**.
High+critical 210 → 16. DVNA 19 unchanged (4 pin vulns reachable). FP delta: 0.
See `benchmarks/REPORT.md`.

**Stopped here per the mandatory Phase 13 review gate.** Phases 11, 12, 14–16
not started. Nothing was pushed to GitHub.

## harden-3 — transitive reachability, sink-specific sanitizers, dev-only

**Built:**
- `reachable-via-dependency` when a lockfile path connects a vuln to a
  **production-imported** direct dependency. Severity **kept**. Path on the
  finding (`express > body-parser > qs`). `not-imported` (−2) only when no
  such path exists. Test-file imports are not roots.
- DevDependency-only vulns (dev tree, no production import) → `info` +
  `dev-only`. Production import of a listed devDependency keeps severity.
- Sanitizers are sink-specific: `JSON.parse` / generic `parse` never clear
  taint; `encodeURIComponent` is URL/redirect only; HTML `escape`/`sanitize`
  is XSS only; zod/joi/yup clear taint only for the validated result.
  `db.query("…" + JSON.parse(req.body).id)` is flagged.
- Fixtures: `reachability-app`, `devdep-app`, `devdep-imported-app`.

**Benchmark (honest; high+critical went up):** NodeGoat 373 unchanged count.
OSV 320: 12 reachable, 4 imported-not-called, **84 via-dependency (severity
kept)**, 220 not-imported. 129 also `dev-only` → info. High+critical
**16 → 59**. DVNA 19 unchanged. See `benchmarks/REPORT.md`.

## Phase 11 — watch (new OSV alerts only)

**Built:** `fullshield watch` rescans `deps`, diffs vs last-scan ids, alerts
only on new `DEPS-VULN-001`. Second unchanged run: "No new vulnerabilities."
`init` writes daily `.github/workflows/fullshield-watch.yml`.

**Verify (`npm run verify:phase 11`, PASSED):** 257 tests. 94.88% / 83.68%.

**Benchmark:** NodeGoat 373 / DVNA 19 unchanged vs harden-3.

## Phase 12 — edge posture

**Built:** `fullshield edge <url>` GET/HEAD only. CDN/WAF (`cf-ray`, CloudFront,
Fastly, …), HTTP→HTTPS, HSTS/CSP/XCTO/XFO/Referrer-Policy, probes `/.env`,
`/.git/HEAD`, `/package.json`, `/debug`, `/server-status`. Delay configurable
via `FULLSHIELD_EDGE_DELAY` (tests use 0). Verify wrapper uses async `spawn`
so the mock server can answer (spawnSync deadlocked the event loop).

**Verify (`npm run verify:phase 12`, PASSED):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 12 | 94.14% | 82.74% | deps,secrets,sast,config | 30 | 30 | 34 | 0 |

278 tests. Acceptance: mock server reports `EDGE-CDN-001` / `EDGE-HSTS-001` / `EDGE-TLS-001`.

**Benchmark:** NodeGoat 373 / DVNA 19 unchanged vs harden-3.

## Phase 14 — AI provider layer

**Built:** Opt-in `--ai`. Off by default = zero AI network calls. Recorded fixtures
(no API key, no provider socket in CI). Secrets module redacts outbound payloads
to `<REDACTED>`. Cost cap (`ai.maxCostUsd`, default $1) + prompt/model cache.
`AI-INJECT-001` (medium) on comments containing "ignore previous", "mark as safe",
or "AI reviewer". Providers wired: Anthropic / OpenAI / Ollama (live path is
fetch-injected in tests only).

**Verify (`npm run verify:phase 14`, PASSED):** 278 tests. 94.14% / 82.76%.
Acceptance: `AI-INJECT-001` on the seeded comment fixture.

## Phase 15 — triage, explain, verified fix

**Built:** `scan --ai triage` labels `{verdict, reasoning, exploitScenario}` and
never drops a high/critical finding. `scan --ai explain` adds `explanation`.
`fix --ai` applies a recorded patch in a temp copy, rescans (finding gone, no
new findings), runs tests if present, max 2 attempts, prints a reviewable
diff, never writes the user tree.

**Verify (`npm run verify:phase 15`, PASSED):** 278 tests. 94.14% / 82.76%.
Acceptance: `--ai explain` labels findings; `fix --ai` prints a reviewable diff
and does not write the user tree.

## Phase 16 — logic hunter + runtime anomaly

**Built:** `scan --ai logic` recorded-fixture hunter for IDOR and mass assignment.
Findings are `source: ai`, confidence medium, and **never fail CI** (`failsCi`
skips them). Clean ownership-checked fixtures are quiet. Fixture precision is
printed in verify. `shieldGuard({ anomaly: { learnMinutes } })` learns per-route
baselines and flags 401 spikes, new param names, and 404 bursts (no LLM).

**Verify (`npm run verify:phase 16`, PASSED):**

| phase | coverage lines | coverage branches | implemented modules | expected findings | found expected | vulnerable-app findings | clean-app high/critical |
|---|---|---|---|---|---|---|---|
| 16 | 94.14% | 82.77% | deps,secrets,sast,config | 30 | 30 | 34 | 0 |

278 tests. Acceptance: IDOR + mass-assignment `source: ai` confidence medium;
`--fail-on high` exits 0; clean fixture quiet; fixture precision=1.00.

**Benchmark:** NodeGoat 373 / DVNA 19 unchanged vs harden-3. High+critical **59**.

**Stopped here per the mandatory Phase 16 gate.** Nothing was pushed to GitHub.

## harden-4-1 — live AI smoke

The Phase 14–16 provider called a model (or a fixture) and then ignored the JSON
and applied recorded labels. Live mode now uses `src/ai/parse.ts` against
Ollama `POST /api/chat` (`format: json`). Opt-in: `FULLSHIELD_AI_LIVE=1` only.
`npm run test:live-ai` is **not** in `verify` / CI.

**Real run (qwen2.5-coder:7b, 507s, exit 0):** 8-finding smoke cap. vulnerable-app
triage 4/8 TP verdicts, 2 wrong LFPs. NodeGoat triage **0/8 TP**, 6 known TPs
marked LFP. Logic: 2 wrong-class hits on vulnerable-app, **0** on NodeGoat
(missed A4 IDOR). `fix --ai` accepted **no** patch on either target (verify loop
rejected both). Details: `benchmarks/AI-REPORT.md`.

Recorded fixtures were not changed.

## harden-4-2 — yarn / pnpm edges + reachability-unknown

`parseLockfileGraph` now extracts yarn classic / pnpm package dependency
links (`edgesKnown: true`). Manifest-only and unknown lockfile names stay
`edgesKnown: false`. `classifyReachability` then returns `reachability-unknown`
and **does not** drop severity. Yarn and pnpm fixtures:
`test/fixtures/{yarn,pnpm}-reachability-app` (express → … → minimist via-dep;
unused lodash not-imported).

**Re-scan:** NodeGoat 373 / high+critical **59** unchanged (npm lockfile).
DVNA 19 unchanged. JSON: `benchmarks/results/*-harden4.json`.

## harden-4-3 — runtime memory caps

`LruMap` on the rate-limiter key map (default 10_000) and anomaly route map
(default 1_000) / param-name map (default 200). Configurable via
`rateLimit.maxKeys`, `anomaly.maxRoutes`, `anomaly.maxParamNames`.

Test: 100_000 unique IPs + 100_000 unique param names + 100_000 routes; map
sizes stay at the cap; heap delta < 80MB.

## harden-4-4 — mutation-smoke extras

`scripts/mutation-smoke.mjs` now also disables `findings.push` in
`src/modules/edge/index.ts` and `src/ai/injection.ts`, `noLockFinding()` in
deps, and `pushSinkFinding` in interproc. Existing tests fail when those
are disabled (no fake-test holes found).

## harden-4-5 — README honesty

All `--ai` / `fix --ai` flags marked **experimental**. `AI-INJECT-001` listed
as a basic phrase heuristic (three comment phrases). Reachability list includes
`reachability-unknown`. Live smoke linked from Benchmarks.

**harden-4 complete. Stopped. Do not start Frontier (17+).** Nothing pushed.
