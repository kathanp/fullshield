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
| FS-E000 | Any other command error | Read the message. Re-run with `--debug` if you need the stack. |
