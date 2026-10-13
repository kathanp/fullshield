# CONFIG-BODYLIMIT-001

**express.json() without a size limit.** CWE-770.

## Remediation

Pass { limit: '100kb' } (or your budget).

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
