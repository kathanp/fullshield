# SAST-CRYPTO-001

**Math.random for tokens, or md5/sha1 near a password.** CWE-327.

## Remediation

Use crypto.randomUUID / randomBytes and a modern KDF.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
