# AGENTS-TOOL-001

**Untrusted input in a tool argument.** CWE-1426. Requires `FULLSHIELD_EXPERIMENTAL_AGENTS=1` and `--modules agents`.

Request data is placed in a tool or function `arguments` or `parameters` value. A file that only contains the words `prompt` or `system` is not this finding.

## Remediation

Do not pass request data as a tool argument. Pass a value the application checked.
