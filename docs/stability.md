# Public contract

This is the surface a 1.0.0 tag freezes. Breaking a row here costs a 2.0. Experimental flags, commands, and fields are labeled below and are not part of that promise.

Phase 56 (EPSS / CISA) is not in this release. Default scan does not contact `api.first.org` or `www.cisa.gov`.

## Stable

- CLI: `scan`, `fix`, `init`, `sbom --format cyclonedx`, and the flags named in `fullshield --help` without the word experimental.
- Config keys accepted by `fullshield.config.json`: `modules`, `failOn`, `ignore`, `defaultExcludes`, `excludes`, `baseline`, `notify`, `deps`, `ai`, `sast`. Unknown keys are rejected.
- Exit codes: `0` finished and under `--fail-on`, `1` a finding is at or above `--fail-on`, `2` the command failed (`FS-E`).
- Error codes `FS-E000` through `FS-E016`. Each code has one meaning in [errors.md](errors.md). `FS-E013` through `FS-E016` are only raised by experimental commands, and the numbers will not be reused.
- Library exports and command help text recorded in `api/fullshield.api.json`.
- `Finding.source`: `deterministic`, `ai`, `user-rule`, `npm-audit`, `semgrep`, `osv-scanner`, or `sarif`. An ingest tool name that is not in that list is stored as `sarif`. The original tool name stays in `sources`.
- `Finding.suppressedBy`: `types` or `model:<package>`.
- `ScanResult.metadata.modulesRequested` and `modulesRun` are `readonly`. Callers do not mutate them.

## Experimental (not frozen)

Anything gated by `FULLSHIELD_EXPERIMENTAL_*` or `--experimental-*`. Exit code `3` exists only while the time-budget flag is on. Config keys `types` and `semgrepRules` are read only for those flags.

The flag list in `api/fullshield.api.json` is a record of what this commit implements. It is not a promise that each flag stays.
