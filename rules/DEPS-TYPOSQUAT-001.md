# DEPS-TYPOSQUAT-001

**Direct dependency whose name is 1 edit from a popular package and is not itself in the static top-packages list.** CWE-1357.

## Remediation

Confirm the name is intentional. Transitive names, hyphen-only variants, and packages that appear in the larger top-packages list are not flagged.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
