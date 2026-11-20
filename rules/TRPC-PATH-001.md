# TRPC-PATH-001

**tRPC procedure input reaches a path.** CWE-22. Requires `FULLSHIELD_EXPERIMENTAL_TRPC=1` and `--modules trpc`.

A procedure `.query` or `.mutation` passes its `input` into a file path call. An allowlist that returns before the call is not this finding.

## Remediation

Pass a checked path or a constant. Do not pass the raw procedure input into a file path.
