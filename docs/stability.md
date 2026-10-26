# Public contract

This is the surface the 1.x line freezes. Breaking a row in "Stable" requires 2.0.0.
Anything in "Experimental" or "Internal" may change in any minor release.

1.0.1 corrected this file. 1.0.0 listed some values in Stable that only experimental
flags produce. Those rows moved to Experimental. No stable behavior changed.
See CHANGELOG 1.0.1.

Phase 56 (EPSS / CISA) is not in this release. Default scan does not contact
`api.first.org` or `www.cisa.gov`.

## Stable

### Commands
- `scan`, `fix`, `init`, `sbom --format cyclonedx`, `watch`, `edge`, `notify`, `doctor`.
- The flags each command prints in `--help` that are not labeled experimental.

### Exit codes (scan)
- `0` finished, nothing at or above `--fail-on`.
- `1` a finding is at or above `--fail-on`.
- `2` the command failed (`FS-E` code printed).

### Error codes
- `FS-E000` through `FS-E004`. Each has one meaning in [errors.md](errors.md).
- Code numbers are never reused, including the experimental and internal codes below.

### Config keys (`fullshield.config.json`)
- `modules`, `failOn`, `ignore`, `defaultExcludes`, `excludes`, `baseline`, `notify`.
- `sast.maxFileBytes`.
- `deps.offline`, `deps.cacheDir`.
- Unknown keys are rejected.

### JSON output (`scan --json`)
- Finding fields: `id`, `ruleId`, `module`, `title`, `severity`, `confidence`,
  `file`, `line`, `message`, `remediation`, `references`, `trace`.
- `severity`: `info`, `low`, `medium`, `high`, `critical`.
- `reachability`: `reachable`, `imported-not-called`, `reachable-via-dependency`,
  `not-imported`, `reachability-unknown`, `symbol-reachable`, `symbol-not-called`.
- `source`: `deterministic` only. That is the only `Finding.source` value `src/` assigns
  on a built-in finding (`src/ai/injection.ts`).
- `metadata.modulesRequested` and `metadata.modulesRun` are `readonly`.
- Rule IDs listed as stable in `rules/README.md`. A stable rule ID is never renamed
  or removed in 1.x.

### Library
- Exports in `api/fullshield.api.json` not marked `experimental`.

## Experimental (not frozen)

- Anything gated by `FULLSHIELD_EXPERIMENTAL_*` or `--experimental-*`.
- Exit code `3` (time-budget flag only).
- `FS-E005`–`FS-E009` and `FS-E012`–`FS-E016`: raised only by experimental
  commands or flags.
- `Finding.source` values `ai`, `user-rule`, `npm-audit`, `semgrep`, `osv-scanner`,
  `sarif` (produced by `--ai`, user Semgrep-style rules, and `ingest`).
- `Finding.suppressedBy` (`types`, `model:<package>`) and `suppressed[]`.
- `Finding.priority`, `priorityFactors`, `reachabilityEvidence`, `paths[]`,
  `metadata.incomplete`, `metadata.incompleteModules`, `metadata.skipped`.
- Config keys `ai`, `types`, `semgrepRules`, `sast.sources`, `sast.sanitizers`,
  `deps.capabilityPolicy`.

## Internal (not part of any contract)

- `FS-E010`, `FS-E011`: contributor tooling (`npm run verify`, `quality`, mutation).
- Everything under `bench/`, `scripts/`, `quality/`, `reports/`.

The flag list in `api/fullshield.api.json` records what this commit implements.
It is not a promise that each flag stays.

## Phase 500

Stable rule ids are the rules whose front matter says `stability: stable`. Experimental keys may disappear in a minor. This section does not say the product is complete.

## 1.3.0

1.3.0 adds experimental phases behind their own flags. Stable scan fields in this file are unchanged. Default `scan --json` is unchanged.

## 2.0.1

2.0.1 does not change default `scan --json`. It adds five experimental scanners: HTTP header injection, mail header injection, spreadsheet formula injection, browser-automation control, and dynamic import of request data. Each stays off unless its flag is set. The finding fields in this file are unchanged. No stable rule id is removed.

## 1.8.0

1.8.0 does not change default `scan --json`. A lockfile that does not parse no longer aborts the scan. The dev install of `body-parser` moves to 1.20.9 and 2.4.0. The finding fields in this file are unchanged.

## 1.7.0

1.7.0 adds findings to default `scan --json` for a `sql` tagged template on postgres, mysql2, `@databases/pg`, slonik, or drizzle-orm, and for `execFile` / `execFileSync` when the command path is request data. The finding fields in this file are unchanged. `FULLSHIELD_EXPERIMENTAL_DEEP` (`scan --experimental-deep`) adds matches on the existing XSS, SSRF, path, redirect, JWT, and prototype rules and stays off unless that flag is set.

## 1.6.0

1.6.0 adds findings to default `scan --json` for `node:sqlite` and `bun:sqlite` exec/prepare, `Bun.spawn`, Bun shell templates, `Deno.Command`, and `evaluate` on mathjs, expr-eval, and vm2. The finding fields in this file are unchanged. The eleven checks in the 1.6.0 changelog stay experimental and off unless their flags are set.

## 1.5.0

1.5.0 adds findings to default `scan --json` for one object field, one nested function, ORM raw queries, and the shell variants named in the changelog. The finding fields in this file are unchanged. `SAST-LDAP-001` and `CONFIG-CORS-002` stay experimental.
