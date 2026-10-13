# SAST-PROTO-001

**Recursive merge of a tainted object without a __proto__ guard.** CWE-1321.

## Remediation

Skip __proto__, constructor, and prototype keys.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
