# TRPC-SQL-001

**tRPC procedure input reaches SQL.** CWE-89. Requires `FULLSHIELD_EXPERIMENTAL_TRPC=1` and `--modules trpc`.

A `publicProcedure` or `procedure` `.query` or `.mutation` passes its `input` into `query` or `execute`. A checked field, a constant, and a file that only contains the words `publicProcedure` and `query` are not this finding. This is not an ownership check.

## Remediation

Pass a checked field or a constant. Do not pass the raw procedure input into SQL.
