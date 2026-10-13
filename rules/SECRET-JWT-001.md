# SECRET-JWT-001

**Hardcoded JWT signing secret.** CWE-798.

## Remediation

Replace the literal with process.env.JWT_SECRET and rotate.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
