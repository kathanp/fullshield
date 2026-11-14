# FullShield roadmap: 3.10.0

Rules for every version:
- One headline capability a user notices on first run.
  3.6.1 is the exception: the items below ship in that one release.
- Removes or merges at least as many FULLSHIELD_EXPERIMENTAL_* flags as it adds.
- The only release gate is: every code change has a test, all six CI jobs are green,
  clean-app stays at 0 findings, and no in-scope ground-truth match is lost on
  NodeGoat, Juice Shop, DVNA, goof, and vulnerable-node. There is no numeric benchmark target.
- Default: at least 14 days between minor versions (x.Y.0). The maintainer can
  override one release by saying "waive the 14-day wait" in the instruction.
  That version's CHANGELOG section then records "14-day wait waived by maintainer."
  Patch versions (x.y.Z) have no wait.
- Node/TS only. Offline-first. No telemetry, no hosted service, no PR-comment bot,
  no new language, no new string-match H/G-style checks.

3.6.1 is published. It holds the unfinished trust baseline and everything that used to be 4.0.0–4.7.0 and 5.0.0. Those old numbers were never tagged. D-77 moved that scope into 3.6.1. This tree is 3.10.0. After 3.7.0, the next plan is three minors, 3.8.0, 3.9.0, and 3.10.0. Each one adds a module. None of them is a 4.0.0 major. A major has to remove or change something already listed as Stable in `docs/stability.md`. A new module does not.

`v3.6.0` is already on `main` (2026-11-02) for the four group flags only. The rest of this section is still open. On 2026-11-03 the maintainer chose one release, numbered 3.6.1, for this whole section (D-77). The version check accepts that patch. The release after 3.6.1 follows R16a again.

---

## 3.6.1: Next release

Already in the `v3.6.0` tag:
- [ X ] `FULLSHIELD_EXPERIMENTAL_SAST_EXTRA`, `_RUNTIME`, `_REPORTS`, and `_AI` turn on the existing checks in that group. Old names still work.

Already shipped in 3.5.5, not rebuilt here:
- [ X ] `src/reporters/sarif.ts` `informationUri` → github.com/kathanp/fullshield.
- [ X ] Opt-in hosts (AI providers, secret-verify endpoints) in `src/net/hosts.ts`, each tied to the flag that enables it. `security-page.md` says all fetched hosts are allowlisted.
- [ X ] `QUALITY.md` Q8 number generated from `quality/baseline.json`.

### Trust baseline
Goal: first reviewed precision number; cut the noise we already know about.
Ships:
- BENCHMARK.md: maintainer-reviewed precision per module and per rule
  (n, repos, date, "one reviewer"). Labels come from bench/review/*.csv (human only).
- Section G/H removal for reviewed precision under 50% (n >= 5) is under Not planned.
- [ X ] Remove H45, H47–H57 (magic-filename "findings").
- [ X ] Merge `FULLSHIELD_EXPERIMENTAL_SUPPLY` into the group switch. Old names stay accepted as aliases for one major.
- [ X ] Experimental flag names in `--help` cut by >= 30%.
Exit criteria:
- [ X ] Experimental flag names in --help down >= 30%.
- Precision published for deps, sast, secrets, config.
- URL audit: 0 NEEDS-HUMAN rows.

### One verify, then stage
Goal: the tag waits about 15–20 minutes, then the maintainer clicks the staged version.
Ships: [ X ] the release path in `RELEASING.md`. The pull request keeps six verify jobs: Ubuntu, macOS, and Windows, on Node 22 and Node 24. Fast-forward `main`. The tag does not run `npm run verify`. No `next` branch update.
Exit criteria:
- A pull request runs those six verify jobs.
- [ X ] A tag push does not run `npm run verify`.

### Default scan
Goal: the default CI gate fails only on findings people trust.
Ships:
- Default --fail-on limited to rules with reviewed precision >= 80% is under Not planned.
  Other rules still report. `gate: false` is already used for not-imported and dev-only deps.
- [ X ] DEPS-VULN-001 with reachability `not-imported` or dev-only → severity info,
  never fails the gate.
- Experimental→default promotions are under Not planned. Their evidence files stay unmet.
- CHANGELOG "Default scan changes": every rule ID added/removed/re-severitied,
  before/after counts per bench app.
Exit criteria:
- NodeGoat default findings under 60 is under Not planned. Zero in-scope ground-truth loss on the five apps is a 3.7.0 bar.
- [ X ] clean-app stays 0.

### CI that doesn't annoy
Goal: fast, and only new problems fail a PR.
Ships:
- [ X ] `scan --diff` + baseline promoted to stable; `init --recommended` uses it.
- [ X ] Content-hash parse cache on by default (local, versioned, corrupt = discard).
- GitHub Action published on Marketplace, pinned by SHA in docs.
Exit criteria:
- Next.js cold p50 < 60s, warm p50 < 15s (bench/perf-v2.json, measured: true).
- A PR touching 1 file in Next.js scans in < 10s.

### Verified fix
Goal: every fix comes with proof.
Ships:
- [ X ] `fix --verify`: apply each patch in a temp copy → re-scan → run project tests →
  status `fixed` | `fixed-tests-fail` | `not-fixed`. Working tree untouched until
  `--apply`.
- [ X ] Dependency bumps: install target version in temp copy, run tests, report
  `upgrade-safe` | `upgrade-breaks-tests`.
- [ X ] `fix --pr`: one gh PR per verified fix. Never merges. Never comments.
Exit criteria:
- >= 70% of high/critical findings in bench apps get a `fixed` patch.
- 0 patches marked `fixed` that the re-scan still reports.

### Install firewall
Goal: stop bad packages before their install scripts run.
Ships:
- [ X ] `fullshield install <pkg>` and an opt-in `preinstall` guard.
- [ X ] Checks before install: OSV MAL- advisories, typosquat, new/changed install
  scripts, missing provenance, publisher change vs previous versions, release age
  below policy. Never executes the package.
- [ X ] Policy in fullshield.config.json: `install.block`, `install.warn`.
Exit criteria:
- The malicious-package replay and the top 500 false-block bar are under Not planned.

### Function-level reachability
Goal: "you call the vulnerable function", not "you import the package".
Ships:
- The 100 human-reviewed rows in `models/vuln-functions.json` are under Not planned. The file stays `{ "rows": [] }`.
- [ X ] Call graph from app code to those functions → `symbol-reachable` /
  `symbol-not-called`.
Exit criteria:
- The 100 cited packages, the 40% downgrade bar, and zero true reachable downgrades are under Not planned.

### Proof of exploit
Goal: turn "reachable" into "confirmed exploitable".
Ships:
- [ X ] `confirm --app` starts the app on 127.0.0.1 and sends harmless canaries
  for SQLi, CMDi, path traversal, and SSRF from a routes file. It marks
  `confirmed-exploitable` | `unconfirmed`. localhost / 127.0.0.1 / own container only.
- [ X ] `unconfirmed` is never shown as a pass.
Exit criteria:
- >= 60% of true in-scope findings on bench apps confirmed.
- 0 writes outside a temp dir; 0 non-local requests.

### Framework-native
Goal: claim the frameworks people actually use.
Ships:
- [ X ] First-class sources/sanitizers: Next.js server actions + route handlers,
  NestJS guards/pipes, Fastify schemas.
- [ X ] docs/compatibility.md: Next, Nest, and Fastify are `ci`. Each has a
  fixture app, and the six-job matrix runs `scripts/framework-ci.mjs` on it.
Exit criteria:
- One fixture app per framework in CI, green on all 6 matrix jobs.
- Precision measured per framework, >= 80%.

### AI-agent guardrail
Goal: Cursor and Claude Code check their own code before committing.
Ships:
- [ X ] MCP server promoted to stable: `check_diff`, `get_findings`, `verified_fix`.
- [ X ] `init --agent cursor|claude` writes the rule file and MCP config.
- [ X ] Agent mode gates only lines changed in the working diff.
Exit criteria:
- [ X ] No live Cursor or Claude Code demo in this release. On 2026-11-05 the maintainer said the first run is the developer's, after the package is on npm. Code and tests are the gate.
- [ X ] MCP tools remain read-only except `verified_fix` writing a temp copy.

### Runtime evidence
Goal: use real execution to cut the last layer of noise.
Ships:
- [ X ] `fullshield record` (staging only): logs which routes/functions run, to a local
  file. No network, no telemetry.
- [ X ] Scan merges recorded evidence: never-executed code → downgraded;
  executed + confirmed → `evidence: prioritized`.
- [ X ] Default severities can change with evidence.
Exit criteria:
- The further 30% drop and the record-overhead bar are under Not planned.

This release also adds commands, flags, and default-scan findings. The earlier patch rule "no new command, flag, rule id, or default-scan finding" does not apply to 3.6.1.

## 3.7.0

Code and tests only. No live demo. No numeric benchmark target. 14-day wait waived by maintainer on 2026-11-05. Each bar below has a test. The release gate is those tests, six green CI jobs, clean-app at 0 findings, and no in-scope ground-truth match lost on the five bench apps. The tag stages the package. The maintainer clicks the staged version on npmjs.com.

- [X] Juice Shop redirect `lib/insecurity.ts:136`: flag `includes()` used as a redirect allowlist. Maintainer decision: `test/unit/modules/sast/bench-misses.test.ts` and `test/unit/modules/sast/phase502-flow2.test.ts` expect `SAST-REDIRECT-002`. Tests cover the bad pattern and a safe `startsWith` / URL-parse pattern.
- [X] Juice Shop `routes/trackOrder.ts`: keep `res.json` silence. Recorded as a known limit in the docs.
- [X] vulnerable-node `views/error.ejs:4`: a template rule for `error.stack` / `err.stack` printed in EJS.
- [X] NodeGoat `app/views/layout.html:75`: carry tainted locals from child views to their `{% extends %}` parent.
- [X] Scorer: a finding with no line only matches a ground-truth row with no line.
- [X] App-config rules `CONFIG-HELMET-001`, `CONFIG-ERRSTACK-001`, `CONFIG-RATELIMIT-001`, `CONFIG-BODYLIMIT-001`, and `CONFIG-DOCKER-ROOT-001` skip `test/`, `__tests__/`, `*.test.*`, `examples/`, `example/`, and `fixtures/`.
- [X] Not-imported check reads `package.json` scripts and dependency bins (`scriptReach`) on the default scan. The experimental flag is not required.
- [X] Clear `requires Node 22.13 or newer` message instead of the `zlib` `crc32` crash.
- [X] NodeGoat noise: a Swig value checked with `isNaN` is not flagged (`contributions.html` 65, 73, 81). `userId` from `req.session` is not flagged. `allocations.html:15` stays, because that `userId` comes from `req.params`. `DEPS-PHANTOM-001` skips an import found only under `test/`.
- [ ] All six CI jobs green on the pull request before merge. Local verify passed. `clean-app` stays at 0 findings. No in-scope ground-truth match lost on NodeGoat, Juice Shop, DVNA, goof, and vulnerable-node.

## Three modules: 3.8.0, 3.9.0, 3.10.0

Not part of 3.6.1 or 3.7.0. 3.8.0 is tagged. 3.9.0 is tagged. 3.10.0 is in this tree and is not tagged. Naming one version is the go for that version's tests. It is not a go for the next version, for a tag, or for npm publish.

The default modules today are `deps`, `secrets`, `sast`, and `config` (`src/core/finding.ts`). These three versions each add one module beside those four. They do not retune baselines, reprints, chains, lockfile install, extra canaries, agent citation, fix statuses, Hono and Koa promotion, or script reachability.

`LLM-001` through `LLM-005` are not reported. `src/exp/sectiong.ts` flags a file that contains both `bull` and `exec`. `src/exp/sectiong.ts` also flags an OpenAPI file that contains the literal path `/admin`. Those checks stay out of the verdict.

Same rules as every other version. One headline. The release gate is a test for each code change, six green CI jobs, clean-app at 0 findings, and no in-scope ground-truth match lost on the five bench apps. There is no numeric benchmark target. At least 14 days between minor versions, unless the maintainer says "waive the 14-day wait" and that version's CHANGELOG records "14-day wait waived by maintainer." Patch versions have no wait. The new module stays behind one flag until the human promotes it. The tag adds that one flag and removes one existing `FULLSHIELD_EXPERIMENTAL_*` flag, so `--help` does not grow. No new string-match H/G-style check. Node.js and TypeScript only. Offline. No telemetry, no hosted service, no pull-request comment bot, no new language. The five agent skills stay out. Business-logic and IDOR findings, container scanning, and the "Not planned" list stay out.

### 3.8.0: `agents` module

Goal: `scan --modules agents` reads the Node app's own model calls. Untrusted input that becomes a system message or a tool argument is a finding. A tool the app registers, whose handler passes that argument to a shell, a file write, or SQL, is a finding.

Ships:
- [X] New module `agents`. Sources are request body, query, params, headers, and cookies. Sinks are a system-role message, a tool or function argument, and a tool handler that forwards that argument to `child_process`, `fs`, or a SQL call.
- [X] The trace crosses a helper in another file, same depth as SAST (5).
- [X] One positive fixture and one negative fixture for each sink. The negative cases are a literal system prompt, user text kept in the user role, and a shell tool whose allowlist rejects the argument.
- [X] `FULLSHIELD_EXPERIMENTAL_LLM` is removed. `LLM-001` through `LLM-005` are not reported.
Exit criteria:
- Each positive fixture reports. Each negative fixture does not.
- clean-app stays 0 with the flag on and with it off.
- Flag off: default `scan --json` is unchanged.
- A file that only contains the word "prompt" or "system" produces no finding.
- Skill files, `~/.cursor`, and any directory outside the project are not read.

### 3.9.0: `workers` module

Goal: `scan --modules workers` treats a background message as a source. A job body or a socket message that reaches SQL, a shell, a path, or a URL is a finding. HTTP `req.body` rules do not see these handlers today.

Ships:
- [X] New module `workers`. Sources are a BullMQ `Worker` job payload, a bee-queue job payload, an SQS record body, and a WebSocket or Socket.IO `message` argument.
- [X] Those values use the existing SQL, command, path, and SSRF sinks. This version adds no new sink.
- [X] One positive fixture and one negative fixture per source. The negative case parses the payload and passes a checked field, or uses a constant.
Exit criteria:
- Each positive fixture reports the sink and names the worker source.
- Each negative fixture reports nothing.
- clean-app stays 0 with the flag on and with it off.
- Flag off: default `scan --json` is unchanged.
- The section G text check that looks for `bull` and `exec` in the same file is not this module and is not the verdict.
- No package is installed and no worker is started.

### 3.10.0: `contract` module

Goal: `scan --modules contract` compares a local OpenAPI file with the routes the app actually registers. A path that exists on only one side is a finding.

Ships:
- [X] New module `contract`. Reads `openapi.yaml` or `openapi.json` in the project. Parses paths and methods.
- [X] Compares that set with the route inventory for Express, Fastify, Nest, and Next. Two rule ids: a spec path with no route, and a route with no spec path.
- [X] Matched method and path produce no finding. A project with no OpenAPI file produces no finding.
Exit criteria:
- A fixture with one extra spec path and one extra route reports those two and stays silent on the paths that match.
- A fixture with no OpenAPI file reports nothing.
- clean-app stays 0 with the flag on and with it off.
- Flag off: default `scan --json` is unchanged.
- The check does not look for the literal string `/admin`. It does not fetch a URL.
- Query parameters and response bodies are out of this version. Path and method only.

## Not planned

These need human review or datasets the maintainer is not providing:

- Maintainer-reviewed precision numbers
- `--fail-on` limited to rules with reviewed precision >= 80%
- Removing Section G/H checks by precision
- Ground-truth reviewed flags and README recall numbers
- 100 human-reviewed rows in `models/vuln-functions.json`, including the 40% downgrade bar and zero true reachable downgrades
- Promoting experimental checks (CSRF, XXE, deserialization) to default
- NodeGoat default findings under 60
- Malicious-package replay and the top-500 false-block check
- 30% drop from recorded evidence, and record overhead under 5% p95
