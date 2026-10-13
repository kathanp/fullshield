# SAST-AUTH-001

**Route handler that touches DB data with no auth-named middleware.** CWE-862.

## Remediation

Low confidence. Add requireAuth (or similar) to the chain.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
