# TRPC-CMD-001

**tRPC procedure input reaches a shell.** CWE-78. Requires `FULLSHIELD_EXPERIMENTAL_TRPC=1` and `--modules trpc`.

A procedure `.query` or `.mutation` passes its `input` into a shell call. A constant command is not this finding.

## Remediation

Pass a constant command, or reject the input before it reaches the shell.
