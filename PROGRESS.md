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
