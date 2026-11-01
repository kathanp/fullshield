# FullShield roadmap: 3.6.0 → 5.0.0

Rules for every version:
- One headline capability a user notices on first run.
- Removes or merges at least as many FULLSHIELD_EXPERIMENTAL_* flags as it adds.
- Ships only when its exit criteria are MEASURED and pass. A miss = the version waits.
- At least 14 days after the previous minor (docs/VERSIONING.md P3).
- Node/TS only. Offline-first. No telemetry, no hosted service, no PR-comment bot,
  no new language, no new string-match H/G-style checks.

---

## 3.6.0: Trust baseline (minor)
Goal: first reviewed precision number; cut the noise we already know about.
Ships:
- BENCHMARK.md: maintainer-reviewed precision per module and per rule
  (n, repos, date, "one reviewer"). Labels come from bench/review/*.csv (human only).
- Remove section G/H checks with < 50% reviewed precision (n >= 5).
- Remove H45, H47–H57 (magic-filename "findings").
- Merge experimental flags into groups: FULLSHIELD_EXPERIMENTAL_SAST_EXTRA,
  _SUPPLY, _RUNTIME, _REPORTS, _AI. Old names stay accepted as aliases for one major.
- Fix src/reporters/sarif.ts informationUri → github.com/kathanp/fullshield.
- Add opt-in hosts (AI providers, secret-verify endpoints) to src/net/hosts.ts with
  the flag that enables each; security-page.md says "all fetched hosts allowlisted".
- QUALITY.md Q8 number generated from quality/baseline.json, not hand-written.
Exit criteria:
- Experimental flag names in --help down >= 30%.
- Precision published for deps, sast, secrets, config.
- URL audit: 0 NEEDS-HUMAN rows.

## 4.0.0: Default Scan v2 (MAJOR)
Goal: default CI gate fails only on findings people trust.
Ships:
- Default --fail-on counts only rules with reviewed precision >= 80%.
  Other rules still report, with `gate: false` in JSON.
- DEPS-VULN-001 with reachability `not-imported` or dev-only → severity info,
  never fails the gate.
- All pending experimental→default promotions land here, together.
- CHANGELOG "Default scan changes": every rule ID added/removed/re-severitied,
  before/after counts per bench app.
Exit criteria:
- NodeGoat default findings 256 → < 60.
- Zero loss of in-scope ground-truth matches on NodeGoat, Juice Shop, DVNA, goof,
  vulnerable-node.
- clean-app stays 0.

## 4.1.0: CI that doesn't annoy (minor)
Goal: fast, and only new problems fail a PR.
Ships:
- `scan --diff` + baseline promoted to stable; `init --recommended` uses it.
- Content-hash parse cache on by default (local, versioned, corrupt = discard).
- GitHub Action published on Marketplace, pinned by SHA in docs.
Exit criteria:
- Next.js cold p50 < 60s, warm p50 < 15s (bench/perf-v2.json, measured: true).
- A PR touching 1 file in Next.js scans in < 10s.

## 4.2.0: Verified fix (minor)
Goal: every fix comes with proof.
Ships:
- `fix --verify`: apply each patch in a temp copy → re-scan → run project tests →
  status `fixed` | `fixed-tests-fail` | `not-fixed`. Working tree untouched until
  `--apply`.
- Dependency bumps: install target version in temp copy, run tests, report
  `upgrade-safe` | `upgrade-breaks-tests`.
- `fix --pr`: one gh PR per verified fix. Never merges. Never comments.
Exit criteria:
- >= 70% of high/critical findings in bench apps get a `fixed` patch.
- 0 patches marked `fixed` that the re-scan still reports.

## 4.3.0: Install firewall (minor)
Goal: stop bad packages before their install scripts run.
Ships:
- `fullshield install <pkg>` and an opt-in `preinstall` guard.
- Checks before install: OSV MAL- advisories, typosquat, new/changed install
  scripts, missing provenance, publisher change vs previous versions, release age
  below policy. Never executes the package.
- Policy in fullshield.config.json: `install.block`, `install.warn`.
Exit criteria:
- Replayed set of past malicious-package incidents (fixture tarballs): >= 90% blocked.
- Top 500 npm packages: 0 false blocks.

## 4.4.0: Function-level reachability (minor)
Goal: "you call the vulnerable function", not "you import the package".
Ships:
- models/vuln-functions.json: advisory → vulnerable export/function for the top 100
  vulnerable npm packages (human-reviewed, cited source per row).
- Call graph from app code to those functions → `symbol-reachable` /
  `symbol-not-called`.
Exit criteria:
- Map covers 100 packages, every row cited.
- >= 40% of dependency findings on bench apps downgraded with evidence.
- 0 true reachable vulns downgraded (checked on ground truth).

## 4.5.0: Proof of exploit (minor)
Goal: turn "reachable" into "confirmed exploitable".
Ships:
- `confirm` promoted from experimental: starts the app locally, sends harmless
  canaries to reachable SQLi, CMDi, path traversal, SSRF; marks
  `confirmed-exploitable` | `unconfirmed`. localhost / 127.0.0.1 / own container only.
- `unconfirmed` is never shown as a pass.
Exit criteria:
- >= 60% of true in-scope findings on bench apps confirmed.
- 0 writes outside a temp dir; 0 non-local requests.

## 4.6.0: Framework-native (minor)
Goal: claim the frameworks people actually use.
Ships:
- First-class sources/sanitizers: Next.js server actions + route handlers,
  NestJS guards/pipes, Fastify schemas.
- docs/compatibility.md: Next, Nest, Fastify move from `not claimed` to `ci`,
  each with a fixture app in the CI matrix.
Exit criteria:
- One fixture app per framework in CI, green on all 6 matrix jobs.
- Precision measured per framework, >= 80%.

## 4.7.0: AI-agent guardrail (minor)
Goal: Cursor and Claude Code check their own code before committing.
Ships:
- MCP server promoted to stable: `check_diff`, `get_findings`, `verified_fix`.
- `init --agent cursor|claude` writes the rule file and MCP config.
- Agent mode gates only lines changed in the working diff.
Exit criteria:
- End-to-end demo in Cursor and Claude Code on this repo: agent introduces a
  vuln → guardrail blocks → verified fix applied.
- MCP tools remain read-only except `verified_fix` writing a temp copy.

## 5.0.0: Runtime evidence (MAJOR)
Goal: use real execution to cut the last layer of noise.
Ships:
- `fullshield record` (staging only): logs which routes/functions run, to a local
  file. No network, no telemetry.
- Scan merges recorded evidence: never-executed code → downgraded;
  executed + confirmed → prioritized.
- Default severities can change with evidence → MAJOR.
Exit criteria:
- On one real app, default findings drop a further >= 30% with 0 loss of
  confirmed-exploitable findings.
- Record overhead < 5% p95 latency in bench.
