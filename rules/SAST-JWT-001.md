# SAST-JWT-001

**jwt.decode used as auth, algorithms includes none, or verify without an allow-list.** CWE-347.

## Remediation

Call jwt.verify with algorithms: ['HS256'] (or your real list).

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
