# FullShield roadmap: 3.6.1

Rules for every version:
- One headline capability a user notices on first run.
  3.6.1 is the exception: the items below ship in that one release.
- Removes or merges at least as many FULLSHIELD_EXPERIMENTAL_* flags as it adds.
- Ships only when its exit criteria are MEASURED and pass. A miss = the version waits.
- At least 14 days after the previous minor (docs/VERSIONING.md P3).
- Node/TS only. Offline-first. No telemetry, no hosted service, no PR-comment bot,
  no new language, no new string-match H/G-style checks.

The next release is 3.6.1. It holds the unfinished trust baseline and everything that used to be 4.0.0–4.7.0 and 5.0.0. There is no separate 4.x or 5.0.0 tag.

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
- Section G/H removal for reviewed precision under 50% (n >= 5) waits in 3.7.0.
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
- Default --fail-on limited to rules with reviewed precision >= 80% waits in 3.7.0.
  Other rules still report. `gate: false` is already used for not-imported and dev-only deps.
- [ X ] DEPS-VULN-001 with reachability `not-imported` or dev-only → severity info,
  never fails the gate.
- Experimental→default promotions wait in 3.7.0. Their evidence files stay unmet.
- CHANGELOG "Default scan changes": every rule ID added/removed/re-severitied,
  before/after counts per bench app.
Exit criteria:
- NodeGoat default findings under 60, and zero in-scope ground-truth loss, wait in 3.7.0.
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
- The malicious-package replay and the top 500 false-block bar wait in 3.7.0.

### Function-level reachability
Goal: "you call the vulnerable function", not "you import the package".
Ships:
- The 100-package `models/vuln-functions.json` map waits in 3.7.0. The file stays `{ "rows": [] }`.
- [ X ] Call graph from app code to those functions → `symbol-reachable` /
  `symbol-not-called`.
Exit criteria:
- The 100 cited packages, the 40% downgrade bar, and zero true reachable downgrades wait in 3.7.0.

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
- The live Cursor and Claude Code demo waits in 3.7.0.
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
- The further 30% drop and the record-overhead bar wait in 3.7.0.

This release also adds commands, flags, and default-scan findings. The earlier patch rule "no new command, flag, rule id, or default-scan finding" does not apply to 3.6.1.

## 3.7.0: waiting bars

Not part of 3.6.1. Nothing here is measured, and nothing here is marked done.

- NodeGoat default findings under 60, with zero loss of in-scope ground-truth matches on NodeGoat, Juice Shop, DVNA, goof, and vulnerable-node. Do not hide dependency reports to hit the count.
- Malicious-package replay: at least 90% of the fixture tarballs blocked. Top 500 npm packages: 0 false blocks.
- `models/vuln-functions.json`: 100 packages, every row cited and human-reviewed. At least 40% of dependency findings on the bench apps downgraded, and zero true reachable vulnerabilities downgraded.
- Promotion files stay unmet until a stored scan meets each file. No flag moves to stable from an empty evidence cell.
- Live Cursor and Claude Code demo: a vulnerability is introduced, the guardrail blocks it, and a verified fix is applied.
- On one real app, recorded evidence drops default findings at least another 30%, with zero loss of confirmed-exploitable findings. Record overhead under 5% p95.
- Default `--fail-on` counts only rules with reviewed precision of at least 80%. Section G/H checks under 50% reviewed precision (n >= 5) can be removed only after that number exists.
- `bench/*/ground-truth.json` stays `"reviewed": false` until a human flips it. Review labels stay blank until a human writes them.
