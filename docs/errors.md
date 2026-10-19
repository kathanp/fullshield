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
| FS-E010 | A custom rules file is missing or fails the JSON schema | Set `FULLSHIELD_EXPERIMENTAL_CUSTOM_RULES=1`. Use `id`, `severity`, `sources`, `sinks`, and `message` only. |
| FS-E011 | `routes` without its flag | Set `FULLSHIELD_EXPERIMENTAL_ROUTES=1` or pass `--experimental-routes`. |
| FS-E012 | `--max-time` without its flag, or not a positive number | Set `FULLSHIELD_EXPERIMENTAL_BUDGET=1`. Exit code 3 means the scan stopped at the budget and nothing scanned was at or above `--fail-on`. Exit code 1 still means a finding met `--fail-on`. An incomplete scan is never a clean result. |
| FS-E013 | `sbom --format spdx` without its flag | Set `FULLSHIELD_EXPERIMENTAL_SPDX=1`. |
| FS-E014 | `ingest` without its flag, or a report file that is not valid | Set `FULLSHIELD_EXPERIMENTAL_INGEST=1`. Other files in the same command are still read when one file is malformed only if the error is per file; a thrown file stops that file. |
| FS-E015 | `--paths` without its flag | Set `FULLSHIELD_EXPERIMENTAL_PATHS=1` or pass `--experimental-paths`. |
| FS-E000 | Any other command error | Read the message. Re-run with `--debug` if you need the stack. |
