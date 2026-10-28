# CLI errors

Current codes only. Which codes are stable is in [stability.md](stability.md). `FS-E010` and `FS-E011` are contributor tooling and not part of the user contract.

FullShield prints `fullshield: FS-E### <message>`. The message is the same text the command already used. A stack trace is included only when you pass `--debug`.

| Code | When | What to do |
|---|---|---|
| FS-E001 | `--fail-on` is not a severity | Use `critical`, `high`, `medium`, `low`, or `info`. |
| FS-E002 | `--modules` names an unknown module | See `fullshield scan --help`. |
| FS-E003 | The scan path is not a directory | Pass the project directory. |
| FS-E004 | `--config` cannot be read | Check the path. |
| FS-E005 | `--github-annotations`, `--junit`, or `--gitlab` without the experimental flag | Set `FULLSHIELD_EXPERIMENTAL_CI_REPORTS=1` or pass `--experimental-ci-reports`. |
| FS-E006 | `diff` without its flag, or a diff input that is not scan JSON | Set `FULLSHIELD_EXPERIMENTAL_DIFF=1` or pass `--experimental-diff`. Pass two `scan --json` files. |
| FS-E007 | `explain` without its flag, or an id prefix that is short, missing, or ambiguous | Set `FULLSHIELD_EXPERIMENTAL_EXPLAIN=1`. Use at least 6 characters that match one finding. |
| FS-E008 | `deps-diff` without its flag, or the git ref has no lockfile | Set `FULLSHIELD_EXPERIMENTAL_DEPS_DIFF=1`. Pass a ref that contains a lockfile. |
| FS-E009 | `sast.sources` or `sast.sanitizers` without the experimental flag | Set `FULLSHIELD_EXPERIMENTAL_CUSTOM_SANITIZERS=1`. `clears` takes B4 class names. |
| FS-E010 | A second `npm run verify` starts in a worktree that already has one | Wait for the verify recorded in `.fullshield-verify.lock` to finish. |
| FS-E011 | `src/` or `test/` changed during verify, quality, or mutation | The run is discarded. Restore the files. Mutation edits a temp copy only. |
| FS-E012 | `ingest` without its flag, or a local report that is not valid JSON for a supported schema | Set `FULLSHIELD_EXPERIMENTAL_INGEST=1` or pass `--experimental-ingest`. The message names the file and the first schema error. Other files are still ingested. |
| FS-E013 | `FULLSHIELD_EXPERIMENTAL_TYPES=1` and the optional `typescript` peer is not installed | Install it with `npm i -D typescript`. The scan keeps the existing receiver heuristics. |
| FS-E014 | `deps --capabilities` without `FULLSHIELD_EXPERIMENTAL_CAPABILITIES=1` | Set the flag. The command only reads installed files. |
| FS-E015 | `--max-time` is not a positive number of seconds while the budget flag is on | Pass a positive number of seconds. Set `FULLSHIELD_EXPERIMENTAL_BUDGET=1` or pass `--experimental-budget`. |
| FS-E016 | User Semgrep-style rules without the flag, a missing `yaml` peer, an unreadable rules file, or an unsupported construct | Set `FULLSHIELD_EXPERIMENTAL_SEMGREP_RULES=1`. Install the optional `yaml` peer. The message names the construct and the rule id. The whole file is rejected. |
| FS-E017 | `npm-audit-diff` without its flag, or the audit file or scan JSON cannot be read | Set `FULLSHIELD_EXPERIMENTAL_NPM_AUDIT_DIFF=1`. Pass `--file` for an `npm audit --json` file you already produced. `--from` is a `scan --json` file. Without `--from` the command reads `.fullshield/last-scan.json`. The command does not run `npm audit`. |
| FS-E018 | `scan --diff` without its flag, or git cannot list the changed files | Set `FULLSHIELD_EXPERIMENTAL_DIFFSCAN=1` or pass `--experimental-diffscan`. A git failure does not scan the rest of the tree. |
| FS-E019 | `schedule install`, `schedule uninstall`, or `schedule status` cannot register, remove, or read the OS timer | The timer is a user LaunchAgent, a user crontab, or a scheduled task. FullShield does not use sudo. |
| FS-E330 | Access-control matrix report while `FULLSHIELD_EXPERIMENTAL_ACLREPORT` is off | Set the flag. The command does not write the report when the flag is off. |
| FS-E341 | Secret allowlist file is missing, not JSON, incomplete, or contains a raw secret | Pass a local allow file. The scanner does not read it when `FULLSHIELD_EXPERIMENTAL_SECRETALLOW` is off. |
| FS-E347 | Patch-diff symbol candidates while `FULLSHIELD_EXPERIMENTAL_PATCHDIFF` is off | Set the flag. The command does not read the diff when the flag is off. |
| FS-E352 | Pull-request dependency flags while `FULLSHIELD_EXPERIMENTAL_DEPRFLAGS` is off, or the input has a score field | Set the flag. Remove any score field. The tokens are a closed set. |
| FS-E000 | Any other command error | Read the message. Re-run with `--debug` if you need the stack. |

## Scan exit codes

| Code | When |
|---|---|
| 0 | The scan finished, and nothing is at or above `--fail-on`. |
| 1 | A finding is at or above `--fail-on`. |
| 2 | The command failed. See the `FS-E` code above. |
| 3 | `FULLSHIELD_EXPERIMENTAL_BUDGET` is on, `--max-time` was reached, and nothing that was scanned is at or above `--fail-on`. Exit code 3 is not a clean scan. |

### `--max-time`

With `FULLSHIELD_EXPERIMENTAL_BUDGET` off, `--max-time` has no effect on output or exit codes.

With the flag on and the budget reached: deps, secrets, and config still run to
completion. SAST finishes the current file and stops taint expansion. JSON has
`metadata.incomplete: true` and `metadata.incompleteModules`. The console prints one
yellow line: `Scan stopped at budget. N files not taint-checked.` A finding at or above
`--fail-on` still exits 1. Otherwise the scan exits 3, which is not a clean scan.
