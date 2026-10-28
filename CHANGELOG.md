# Changelog

All notable changes to FullShield are documented here.

## 3.0.0 — 2026-10-28

### Scheduler

- `schedule install` registers an every-2-hours user timer (LaunchAgent, user crontab, or Task Scheduler), creates `fullShieldReport/`, and adds that folder to `.gitignore` once. It does not use sudo and it does not stay running.
- `schedule run` writes `fullShieldReport/fullShieldReport_YYYYMMDD_HHMM.md` in local time and keeps the newest 60 reports. A standing finding does not fail the run.
- `schedule status` and `schedule uninstall` inspect or remove the timer. Uninstall leaves the reports and the `.gitignore` line.
- `scan` does not create `fullShieldReport/` or edit `.gitignore`. Default `scan --json` finding keys are unchanged.

## 2.4.0 — 2026-10-28

### Workspaces and policy

- Phase 554: multi-workspace repos scan each workspace lockfile by default (single-package apps unchanged vs 2.3.0).
- Phase 555: `templates/policy/fullshield.policy.json` starter pack; loaded when `profile` is `recommended` or `ci-strict`.
- Phase 556: `init --ci` writes Action + config (+ policy with `--recommended`); optional `gh` PR; `--no-pr` skips it; never posts PR comments.

## 2.3.0 — 2026-10-28

### Adoption

- Phase 550: `templates/action/` composite GitHub Action (pinned `fullshield`, SARIF upload, optional baseline cache). Does not post pull-request comments. `init --recommended` can write the Action-based workflow.
- Phase 551: README “Verify in 60 seconds” path for `fullshield@2.3.0` with npm provenance note.
- Phase 552: README speed claims cite `bench/perf-v2.json` only (Next.js cold target still unmet).
- Phase 553: config `profile` (`recommended` | `ci-strict` | `pr-fast` | `prod-monitor`), `init --recommended`, and doctor warning when many experimental flags are set without a profile.

Default `scan --json` finding keys stay identical to 2.2.0.

## 2.2.0 — 2026-10-27

### Performance

- Phase 545: every scan shares one AST per source file (parse at most once).
- Phase 546: `deps`, `secrets`, `config`, and `sast` run concurrently with a deterministic merge.
- Phase 547: lazy taint walks only files on a path from a request source (depth ≤ 5).
- Phase 548: `FULLSHIELD_EXPERIMENTAL_PERF2` enables a worker parse pool (`FULLSHIELD_PARSE_WORKERS` caps size).
- Phase 549: `FULLSHIELD_EXPERIMENTAL_PERF2` may reuse a local parse cache under the FullShield cache directory. Corrupt entries are discarded.

Default `scan --json` finding keys stay identical. File skipping (`.d.ts`, `dist/`, `.next/`, minified) stays behind `FULLSHIELD_EXPERIMENTAL_PERF2` only.

## 2.1.0 — 2026-10-26

### Experimental

- Phase 540: `SAST-REDIS-001` behind `FULLSHIELD_EXPERIMENTAL_REDIS` (`scan --experimental-redis`). Request data passed to Redis `eval`, `call`, or `sendCommand`. Off by default.
- Phase 541: `SAST-XPATH-001` behind `FULLSHIELD_EXPERIMENTAL_XPATH` (`scan --experimental-xpath`). Request data passed to an XPath `select` or `evaluate`. Off by default.
- Phase 542: `SAST-SEARCH-001` behind `FULLSHIELD_EXPERIMENTAL_SEARCH` (`scan --experimental-search`). Request data in an Elasticsearch or OpenSearch query. Off by default.
- Phase 543: `SAST-OBJECTKEY-001` behind `FULLSHIELD_EXPERIMENTAL_OBJECTKEY` (`scan --experimental-objectkey`). Request data used as an S3 object key or prefix. Off by default.
- Phase 544: `SAST-WORKER-001` behind `FULLSHIELD_EXPERIMENTAL_WORKER` (`scan --experimental-worker`). Request data used as a worker module path or `workerData`. Off by default.

## 2.0.2 — 2026-10-26

### Fixes

- Phase 537: `SAST-CRLF-001` `set` fires only when the receiver is `res`, `resp`, `response`, or `reply`. `setHeader`, `append`, `header`, and `writeHead` stay. `cache.set` does not fire. Off by default.
- Phase 538: `SAST-MAIL-001` `send` fires only on a mail client receiver (`mail`, `transporter`, `transport`, `sg`, `mg`, or a name that contains `mail`). `sendMail` stays. `res.send` does not fire. Off by default.
- Phase 539: `SAST-FORMULA-001` `write` and `format` do not fire on `res`, `resp`, `response`, or `reply`. `stringify`, `writeToPath`, and a `.csv` `writeFile` stay. Off by default.

## 2.0.1 — 2026-10-26

### Experimental

- Phase 532: `SAST-CRLF-001` behind `FULLSHIELD_EXPERIMENTAL_CRLF` (`scan --experimental-crlf`). Request data used as an HTTP header value. A literal value does not fire. Off by default.
- Phase 533: `SAST-MAIL-001` behind `FULLSHIELD_EXPERIMENTAL_MAIL` (`scan --experimental-mail`). Request data in a nodemailer, SendGrid, or Mailgun field. A literal field does not fire. Off by default.
- Phase 534: `SAST-FORMULA-001` behind `FULLSHIELD_EXPERIMENTAL_FORMULA` (`scan --experimental-formula`). Request data written through a csv package or to a `.csv` path. A literal row does not fire. Off by default.
- Phase 535: `SAST-BROWSER-001` behind `FULLSHIELD_EXPERIMENTAL_BROWSER` (`scan --experimental-browser`). Request data passed to Puppeteer or Playwright `goto`, `setContent`, or `pdf`. The flag is the existing phase 101 flag. A literal URL or HTML body does not fire. Off by default.
- Phase 536: `SAST-DYNIMPORT-001` behind `FULLSHIELD_EXPERIMENTAL_DYNIMPORT` (`scan --experimental-dynimport`). `import()` called with request data. A string-literal specifier does not fire. Off by default.

## 1.8.0 — 2026-10-25

### Fixes

- Phase 529: a `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, or the same file in a workspace, that cannot be parsed does not abort the scan. Secrets, SAST, and config still run. A lockfile that parses keeps the same findings.
- Phase 531: the dev installs of `express` and `@modelcontextprotocol/sdk` resolve `body-parser` at 1.20.9 and 2.4.0, outside GHSA-27r3-jxmh-p828. No new runtime dependency. The scanner does not open a server.

## 1.7.0 — 2026-10-25

### New/changed stable findings — may change CI results; use --update-baseline

- Phase 521: `SAST-SQLI-001` also fires for a tagged template whose tag is `sql`, or a member named `sql`, when the file imports `postgres`, `mysql2`, `@databases/pg`, `slonik`, or `drizzle-orm` and an interpolation is request data. A template with no interpolation does not fire. A tag that is not `sql` does not fire. A query that uses placeholders and a separate bound argument stays silent.
- Phase 522: `SAST-CMDI-001` also fires for `execFile` and `execFileSync` when the command path is request data. A string-literal command path does not fire, even when a later argument is request data. `shell: true` is not required for that path. Existing `exec`, `spawn`, Bun, and Deno matches stay as they are.

### Experimental

- Phase 523: `FULLSHIELD_EXPERIMENTAL_DEEP` (`scan --experimental-deep`). Extra matches on existing rule ids, loaded only when the flag is `1`. `SAST-XSS-001` for `end` when the body contains an HTML tag. `SAST-SSRF-001` for `hostname`, `host`, `href`, or `path` on an `http.request` or `https.request` options object. `SAST-PATH-001` for `Bun.file`, and for `glob` or `opendir` when the file uses `fs`. `SAST-REDIRECT-001` for `location`. `SAST-JWT-001` for an empty algorithm list or a non-literal list. `SAST-PROTO-001` for `Object.assign` and `assign`. A call the existing rule already reports is not reported again. Off by default.

## 1.6.0 — 2026-10-25

### New/changed stable findings — may change CI results; use --update-baseline

- Phase 507: `SAST-SQLI-001` also fires for `node:sqlite` `DatabaseSync.exec` / `prepare` and `bun:sqlite` `exec` / `prepare` when request data is concatenated or interpolated. A literal with placeholders and a separate bound argument does not fire. `child_process.exec` stays a command finding.
- Phase 508: `SAST-CMDI-001` also fires for `Bun.spawn`, `Bun.spawnSync`, a Bun `$` template, and `Deno.Command` when the command or args are request data. A literal argv does not fire.
- Phase 509: `SAST-EVAL-001` also fires for `evaluate` on `mathjs`, `expr-eval`, or `vm2`, and for `vm2` `VM` / `NodeVM` when the code argument is not a string literal. An unrelated `evaluate()` does not fire. `mathjs.eval('1 + 2')` stays silent.

### Experimental

- Phase 510: `DEPS-RSC-001` behind `FULLSHIELD_EXPERIMENTAL_RSC` (`scan --experimental-rsc`). Exact React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 in a lockfile. A canary does not fire. Off by default.
- Phase 511: `CONFIG-COOLDOWN-001` behind `FULLSHIELD_EXPERIMENTAL_COOLDOWN` (`scan --experimental-cooldown`). A release-age gate shorter than three days, in that tool's unit. No cooldown file means no finding. Off by default.
- Phase 512: `SUPPLY-IMPLANT-001` behind `FULLSHIELD_EXPERIMENTAL_IMPORTIMPLANT` (`scan --experimental-import-implant`). `setup_bun.js` or `bun_environment.js`, including install scripts and `node_modules` up to 2000 manifests. Off by default.
- Phase 513: `DEPS-VERINFLATE-001` behind `FULLSHIELD_EXPERIMENTAL_VERINFLATE` (`scan --experimental-ver-inflate`). Lockfile major 9999+ or patch 999 or 9999. Off by default.
- Phase 514: `AGENT-UNICODE-001`, `AGENT-INJECT-001`, `AGENT-EXFIL-001`, and `AGENT-SHELL-001` behind `FULLSHIELD_EXPERIMENTAL_AGENTRULES` (`scan --experimental-agent-rules`). Named agent instruction files only. Off by default.
- Phase 515: `SAST-AGENTSPAWN-001` behind `FULLSHIELD_EXPERIMENTAL_AGENTSPAWN` (`scan --experimental-agent-spawn`). A coding agent launched with a permission bypass in the same call. Off by default.
- Phase 516: `MCP-006`, `MCP-007`, and `MCP-008` behind `FULLSHIELD_EXPERIMENTAL_MCPPOISON` (`scan --experimental-mcp-poison`). Secret elicitation, a shell or instruction default, and a duplicated tool name. `MCP-001`–`MCP-005` are unchanged. Off by default.
- Phase 517: `CONFIG-VITEFS-001` behind `FULLSHIELD_EXPERIMENTAL_VITEFS` (`scan --experimental-vite-fs`). `server.fs.strict: false` or a filesystem root in `server.fs.allow`. Off by default.
- Phase 518: `SAST-HOST-001` behind `FULLSHIELD_EXPERIMENTAL_HOSTPOISON` (`scan --experimental-host-poison`). Host or X-Forwarded-Host copied into an absolute redirect or mail URL. Off by default.
- Phase 519: `SAST-MARKUP-001` behind `FULLSHIELD_EXPERIMENTAL_MARKUP` (`scan --experimental-markup`). markdown-it `html: true` or marked, rendering request data. Off by default.
- Phase 520: `SAST-TRUSTHOST-001` behind `FULLSHIELD_EXPERIMENTAL_TRUSTHOST` (`scan --experimental-trust-host`). Auth.js `trustHost: true`. Off by default.

## 1.5.0 — 2026-10-24

### New/changed stable findings — may change CI results; use --update-baseline

- Phase 503: one object field and one nested function are part of the default scan. The nested function carries request data, not `process.argv`. A field counts on a read after the assignment. `FULLSHIELD_EXPERIMENTAL_FLOW2` and `scan --experimental-flow2` stay accepted and do not turn this off. Against 1.4.0, NodeGoat gains `SAST-XSS-001` at `app/views/allocations.html:15` and `app/views/login.html:110`. vulnerable-app stays 38, clean-app stays 0, and juice-shop, dvna, goof, and vulnerable-node stay the same.
- Phase 504: ORM raw queries, `` exec(`…${x}`) ``, `spawn` of `sh -c`, execa `shell: true`, and zx `$.raw` are part of the default scan. `FULLSHIELD_EXPERIMENTAL_SAST_GAPS` and `scan --experimental-sast-gaps` stay accepted and do not turn this off. No new rule id.

### Experimental

- Phase 505: `SAST-LDAP-001` behind `FULLSHIELD_EXPERIMENTAL_LDAP` (`scan --experimental-ldap`). A string-literal filter does not fire. Off by default.
- Phase 506: `CONFIG-CORS-002` behind `FULLSHIELD_EXPERIMENTAL_CORSREFLECT` (`scan --experimental-cors-reflect`). A fixed origin does not fire. `origin: '*'` with credentials stays `CONFIG-CORS-001`. Off by default.

## 1.4.0 — 2026-10-24

### Experimental

- Phase 501: `scan --diff` behind `FULLSHIELD_EXPERIMENTAL_DIFFSCAN`. The scan reads the changed file, one relative-literal import, and the files that import the changed file. A request value returned from the changed file still reaches a sink in the importer. A git failure is `FS-E018` and does not scan the rest of the tree. Default scan output is unchanged.
- Phase 502: one object field and one nested function behind `FULLSHIELD_EXPERIMENTAL_FLOW2`. Existing injection rules use that path. `JSON.parse` does not clear the value. Default scan output is unchanged.

## 1.3.1 — 2026-10-24

### Dev

- Autopilot writes `docs/FEATURES.md` and requires approval of that file before any spec edit. Default scan output is unchanged.

## 1.3.0

### Experimental

- Phases 252–260 and 262–270: field-sensitive heap, call summaries, async flow, route model, per-class taint labels, IR types, dominating guards, dependency call graph, advisory symbol rows, machine-checkable proofs, Semgrep disagreement export, metamorphic variants, precision gate, shared sink catalog, runtime-observed reachability, incremental queries, and workspace shards. Each analysis stays behind its own `FULLSHIELD_EXPERIMENTAL_*` flag. Default scan output is unchanged. Phase 261 group flags alias the per-phase npm flags for one minor release. Phase 266 records 50 pinned repos in `bench/realworld-v2.json` and does not clone or install them.
- Phases 271–465 and 467–500: deeper analysis, codemods, and local dev checks, each behind its own `FULLSHIELD_EXPERIMENTAL_*` flag or an unpackaged script. Default scan output is unchanged. Phase 466 stays parked until a human names ten holdout repos. It does not write `bench/holdouts.json`.

## 1.2.0

### Experimental

- Phase 105: committed credential files behind `FULLSHIELD_EXPERIMENTAL_CREDFILES` (`SECRET-FILE-002` through `SECRET-FILE-007`). Off by default. Default scan output is unchanged.
- Phase 95: disabled TLS verification behind `FULLSHIELD_EXPERIMENTAL_TLS` (`SAST-TLS-001`, `SAST-TLS-002`). Off by default. Default scan output is unchanged.
- Phase 96: crypto v2 behind `FULLSHIELD_EXPERIMENTAL_CRYPTO2` (`SAST-CIPHER-001`, `SAST-CIPHER-002`, `SAST-RSA-001`, `SAST-JWT-002`). Off by default. Default scan output is unchanged.
- Phase 102: Electron window settings behind `FULLSHIELD_EXPERIMENTAL_ELECTRON` (`CONFIG-ELECTRON-001`, `CONFIG-ELECTRON-002`, `CONFIG-ELECTRON-003`). Off by default. Default scan output is unchanged.
- Phase 104: vendored library files behind `FULLSHIELD_EXPERIMENTAL_VENDORED` (`DEPS-VENDORED-001`). Off by default. Default scan output is unchanged.
- Phase 97: server-side template injection behind `FULLSHIELD_EXPERIMENTAL_SSTI` (`SAST-SSTI-001`) and a RASP template-source hook (`RASP-SSTI-001`) on `ejs`, `pug`, and `nunjucks`. Off by default. Default scan output is unchanged.
- Phase 71: RASP hooks for MongoDB and Mongoose write and aggregate methods, Axios verbs and `axios.create()`, `undici.request`, and `undici:request:create`. Off unless `FULLSHIELD_EXPERIMENTAL_RASP=1`.
- Phase 72: in-request DNS pin (`dnsPinTtlMs`, default 60 seconds) refuses a later private address for a host already resolved in that request.
- Phase 99: webhook verifiers behind `FULLSHIELD_EXPERIMENTAL_WEBHOOK` (`SAST-WEBHOOK-001`). Off by default. Default scan output is unchanged.
- Phase 100: session fixation behind `FULLSHIELD_EXPERIMENTAL_SESSION2` (`SAST-SESSION-002`). Off by default. Default scan output is unchanged.
- Phase 98: secret logging behind `FULLSHIELD_EXPERIMENTAL_LOGLEAK` (`SAST-LOGLEAK-001`). Off by default. Default scan output is unchanged.
- Phase 103: Next.js boundary behind `FULLSHIELD_EXPERIMENTAL_NEXT` (`SAST-NEXT-001`, `CONFIG-NEXT-001`, `CONFIG-NEXT-002`, `SECRET-NEXTPUB-001`). Off by default. Default scan output is unchanged.
- Phase 101: browser JavaScript behind `FULLSHIELD_EXPERIMENTAL_BROWSER` (`SAST-DOMXSS-001`, `SAST-REACT-001`, `SAST-POSTMSG-001`, `SAST-TOKENSTORE-001`). Off by default. Default scan output is unchanged.
- Phase 106: unfixed dependencies behind `FULLSHIELD_EXPERIMENTAL_HEALTH` (`DEPS-UNFIXED-001`). Off by default. Default scan output is unchanged.
- Phase 107: IDOR hints behind `FULLSHIELD_EXPERIMENTAL_IDOR` (`SAST-IDOR-001`). Off by default. `source: rule` never fails CI. Default scan output is unchanged.

## 1.0.1 — 2026-10-20

Documentation-only release. Scanner behavior, default `scan --json` output, and exit
codes are unchanged. `default-scan-diff` against 1.0.0 is empty.

### Contract correction (docs/stability.md)

1.0.0's stability.md listed values in Stable that only experimental flags produce.
That was a documentation error. This release moves them to Experimental.

Moved from Stable to Experimental:
- `Finding.source` values `ai`, `user-rule`, `npm-audit`, `semgrep`, `osv-scanner`, `sarif`.
- `Finding.suppressedBy` (`types`, `model:<package>`).
- Error codes `FS-E005`–`FS-E009`, `FS-E012`–`FS-E016`.
- Config keys `ai`, `sast.sources`, `sast.sanitizers`.

Moved to Internal: `FS-E010`, `FS-E011` (contributor tooling only).

Added to Stable (shipped and documented as stable since 0.1.0 or 0.2.0): `watch`, `edge`,
`notify`, `doctor`, and the core `scan --json` finding fields.

If you depended on a moved value, it still works in 1.0.1. It may change in a later minor.

### Documentation

- `CAPABILITIES.md` rewritten. The 1.0.0 file described 0.1.1 and carried finding
  counts that no longer match. It now links to generated files instead of copying numbers.
- `docs/demo.md` and `BENCHMARK.md` regenerated from runs at 1.0.1.
- `COMPARISON.md` is marked not citable until the Semgrep run is re-checked.
- History notes moved to `docs/history/`.
- Corrected stale lines in `errors.md`, `QUALITY.md`, `priority.md`, `NOISE-REPORT.md`,
  and `CONTRIBUTING.md`.

### 1.0.0 notes corrected

- The 0.2.0 entry said 0.3.0 and 0.4.0 were not tagged. That was true when written.
  Both were tagged later.
- 1.0.0 said Phases 52 and 78 were "merged locally". Both are in the `v1.0.0` commit
  `d654c8b6f155bec88b2327a62402f0b35feb277d`, which contains `5a0d006` (phase 52) and
  `4966d8b` (phase 78).
- Phase 77 is in 1.0.0 as `scripts/realworld-diff.mjs`. It is a dev gate and has no scan flag.
- Phase 81 is in 1.0.0 behind `FULLSHIELD_EXPERIMENTAL_MODELS`.
- Phase 82 is in 1.0.0 behind `FULLSHIELD_EXPERIMENTAL_SECRET_CHECK`.
- Phase 84 is in 1.0.0 behind `FULLSHIELD_EXPERIMENTAL_PRIORITY`.
- Phase 89 is in 1.0.0 behind `FULLSHIELD_EXPERIMENTAL_SPDX`.
- Phase 92 is in 1.0.0 as issue forms, companion-tool docs, and required check names. It has no scan flag.
- The Phase 75 and Phase 51 default-scan diffs were empty on every bench app. That shows
  no regression. It does not show either change finds anything on those apps.

### Release check

1.0.0 was tagged before the six-job matrix was confirmed green on `main`.
The six required checks in `docs/branch-protection.md` passed on pull request #18:
https://github.com/kathanp/fullshield/actions/runs/39514123297
The same six checks passed on the changelog commit:
https://github.com/kathanp/fullshield/actions/runs/39521633354
`v1.0.1` is `dc2b719` on `main`. Publish succeeded:
https://github.com/kathanp/fullshield/actions/runs/39529799316
npm published `1.0.1` at 2026-10-21T02:43:27Z with SLSA provenance.

## 1.0.0 — 2026-10-20

1.0.0 freezes the stable CLI, config keys, exit codes, error codes `FS-E000`–`FS-E016`, and the library exports in `api/fullshield.api.json`. The promise is [docs/stability.md](docs/stability.md).

Experimental features stay behind `FULLSHIELD_EXPERIMENTAL_*` and are not part of that promise. Phase 56 (EPSS / CISA) is not in this release.

Reviewed recall on untouched apps is not in this release. The stored Next.js cold scan remains 71.7 seconds.

### Precision sampling (dev tooling)

Phase 76 adds `scripts/precision-sample.mjs` and `scripts/precision-report.mjs`. Neither script nor `bench/precision/` is in the npm package. The sampler writes `label`, `reviewer`, and `note` as null. Default scan findings are unchanged.

### Provenance signals

Phase 87 adds informational `SUPPLY-PROV-001` when `FULLSHIELD_EXPERIMENTAL_PROVENANCE=1`. Severity is medium. The signal is not a malicious-package claim. Default scan keys are unchanged with the flag off.

### Experimental ingest

Phase 83 reads local Semgrep, npm audit, OSV-Scanner, and SARIF files and dedupes them when `FULLSHIELD_EXPERIMENTAL_INGEST=1`. It does not run those tools, does not fetch, and does not change their severity. Default scan is unchanged. `fullshieldPriority` is not set.

### Phase 86 — dependency capability profile (experimental)

`FULLSHIELD_EXPERIMENTAL_CAPABILITIES=1` adds `fullshield deps --capabilities`, capability notes on `deps-diff`, and `SUPPLY-CAP-001` when `deps.capabilityPolicy` denies a statically read capability. Default scan does not emit `SUPPLY-CAP-001`. Package files are not executed and packages are not installed.

### Fix verification

`FULLSHIELD_EXPERIMENTAL_FIX_VERIFY=1` (or `fix --experimental-fix-verify`) re-scans each proposed fix and each `explain` diff in memory. A patch is `removes-finding`, `does-not-remove`, or `introduces-finding`. A patch that introduces a finding is never written. `does-not-remove` needs `--force-unverified`. Dependency overrides and bumps are checked against the OSV cache only. Default scan output is unchanged.

### Experimental

Phase 90 reads user-supplied Semgrep-style YAML behind `FULLSHIELD_EXPERIMENTAL_SEMGREP_RULES`. Default scan is unchanged. Results may differ from Semgrep.

### Developer loop

`fullshield dev` is off unless `FULLSHIELD_EXPERIMENTAL_DEV=1`. It prints findings that appeared or went away after a save. Default scan output is unchanged.

### Quality gate

Phase 94 adds `npm run quality` (Q1–Q12) for contributors. Default scan findings are unchanged.

Phase 85 adds `scan --paths` behind `FULLSHIELD_EXPERIMENTAL_PATHS`. A path lists findings that already exist. It does not add a finding or change severity. Default scan JSON is unchanged when the flag is off.

### New/changed stable findings — may change CI results; use --update-baseline

Phase 75 router-level auth inheritance. Default-scan diff against `bench/snapshots/HEAD.json` (0.4.0) was empty on vulnerable-app, clean-app, and every bench app. Merged (D9).

Phase 51 follows a SQL string or Mongo filter returned from another file. Default-scan diff against `bench/snapshots/HEAD.json` (0.4.0) was empty on vulnerable-app, clean-app, and every bench app. Merged (D9).

Phase 50 flags Swig `{{ }}` when the view engine is Swig, including consolidate. NodeGoat gains 12 `SAST-XSS-001` keys on profile and contributions fields. `{{csrftoken}}` is not reported. Merged (D15).

Phase 52 adds `DEPS-PHANTOM-001` and `DEPS-LOCKMISMATCH-001` with import or manifest line numbers. Test, script, and seed imports declared in devDependencies are low severity. clean-app declares cors, express-rate-limit, and jsonwebtoken. Merged locally (D16).

Phase 65 taint summaries are already on this branch. The 5-second nest and undici target was not met.

Phase 78 cold-scan work stays behind `FULLSHIELD_EXPERIMENTAL_PERF2`. Merged locally. The quiet-machine speed comparison is not done, so the flag is not claimed to be faster.

### Phase 80 — type-aware receivers

`FULLSHIELD_EXPERIMENTAL_TYPES=1` or `scan --experimental-types` loads the optional `typescript` peer and suppresses sink calls whose receiver resolves to a non-sink type (`Array`, `Map`, a user class). Mongoose models and `any` stay. Suppressed findings are listed in JSON `suppressed[]` with `suppressedBy: "types"`. The flag off leaves scan JSON unchanged. A missing `typescript` install prints FS-E013 and keeps the heuristics.

Phase 79 time budget stays behind `FULLSHIELD_EXPERIMENTAL_BUDGET`. `scan --max-time` stops SAST taint, still finishes deps, secrets, and config, and exits 3 when nothing scanned meets `--fail-on`. That exit is not a clean scan. A finding at or above `--fail-on` still exits 1. The flag off leaves output and exit codes unchanged.

## 0.4.0 — 2026-10-18

Phase 46 still enforces Node >= 22.13 in `engines`, `doctor`, and CI. Phase 47 still owns the console view.

### New/changed stable findings — may change CI results; use --update-baseline

Same-function Mongo filters are reported by the existing `SAST-NOSQLI-001` rule (approved under D7). vulnerable-node gains two keys: `routes/shop.js` lines 41 and 58, both high. Every other tuning app is unchanged. Ground truth was not edited.

### Upgrade plan, evidence, explain, SBOM, supply heuristics, lockfile diff, modern lockfiles

Phases 49, 61, 60, 66, 70, 62, and 63. The upgrade plan is a sentence built from OSV `fixed` versions. The other six are off unless their `FULLSHIELD_EXPERIMENTAL_*` flag is set. Default `(ruleId, file, line, severity)` keys are unchanged.

### Validation, workspaces, custom taint, summaries, SARIF

Phases 53, 54, 64, 65, and 74. Each stays off unless its flag is set. Phase 54 reads `package.json` workspaces. Phase 65 caches taint summaries; the 5-second nest and undici target was not met. Default scan keys stay the same when the flags are off.

### Unused direct dependencies

A scan names direct `dependencies` that no project file imports and that no imported package requires. Imported and imported-not-called packages stay out. `fix` prints the removal plan and writes nothing. `fix --unsafe` deletes those names from `package.json` only, leaves the lockfile alone, and prints `run npm install`. The finding list is unchanged, including a `DEPS-MALICIOUS-001` on an unused package, which stays critical.

### Console

Default console prints the human-decision shown rows (2026-10-18), grouped one row per package name. JSON, SARIF, Markdown, HTML, the baseline, and `--fail-on` stay the full list. `--all` prints every finding, ungrouped. This is not a stable-output change.

Recount on `next` after restore-0.4.0, from `scan --json --offline-safe`, unreviewed. The counts match the 2026-10-18 decision (D4). There is no row-count threshold. The shown rule, the 20-row cap, and severities were not changed.

| app | shown rows | shown findings | folded findings | shown findings by reachability |
|---|---|---|---|---|
| nodegoat | 36 | 62 | 194 | reachable-via-dependency 41, reachable 12, none 8, not-imported 1 |
| juice-shop | 49 | 59 | 46 | none 46, reachable 13 |
| dvna | 14 | 16 | 7 | none 12, reachable 4 |
| goof | 63 | 157 | 114 | reachable-via-dependency 86, reachable 60, none 11 |
| vulnerable-node | 41 | 43 | 20 | none 38, reachable-via-dependency 4, reachable 1 |

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

Phases 36–45 ship in this version. (At the time of writing, `0.3.0` and `0.4.0` were not yet tagged. Both were tagged later.)

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
