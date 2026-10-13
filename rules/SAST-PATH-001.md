# SAST-PATH-001

**Tainted path without path.resolve + prefix check.** CWE-22.

## Remediation

Resolve against a fixed base and require startsWith(baseDir).

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
