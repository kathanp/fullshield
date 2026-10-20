# CLI errors

Current codes only. A command that is not built yet has no row here.

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
| FS-E012 | User Semgrep-style rules without the flag, a missing `yaml` peer, an unreadable rules file, or an unsupported construct | Set `FULLSHIELD_EXPERIMENTAL_SEMGREP_RULES=1`. Install the optional `yaml` peer. The message names the construct and the rule id. The whole file is rejected. |
| FS-E010 | A second `npm run verify` starts in a worktree that already has one | Wait for the verify recorded in `.fullshield-verify.lock` to finish. |
| FS-E011 | `src/` or `test/` changed during verify, quality, or mutation | The run is discarded. Restore the files. Mutation edits a temp copy only. |
| FS-E000 | Any other command error | Read the message. Re-run with `--debug` if you need the stack. |
