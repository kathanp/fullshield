# WORKERS-CMD-001

**bee-queue job payload reaches a shell.** CWE-78. Requires `FULLSHIELD_EXPERIMENTAL_WORKERS=1` and `--modules workers`.

A bee-queue `process` callback passes `job.data` to a shell call. A constant command is not this finding.

## Remediation

Pass a constant command, or a field the application checked. Do not pass the raw job payload to a shell.
