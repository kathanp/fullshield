# AGENTS-SINK-001

**Tool handler forwards its argument to a sink.** CWE-78, CWE-73, or CWE-89. Requires `FULLSHIELD_EXPERIMENTAL_AGENTS=1` and `--modules agents`.

A tool the application registers passes that argument to a shell, a file write, or SQL. A handler that rejects the argument with an allowlist before the call is not this finding. The trace stops after 5 calls.

## Remediation

Do not pass the tool argument to `child_process`, a file write, or SQL. Reject values that are not on an allowlist.
