# SAST-HASH-001

**`bcrypt` cost < 10, `argon2` below OWASP memory/time minimums, or `pbkdf2` iterations below OWASP for the digest.** CWE-916.

Experimental (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`).

## Remediation

Use bcrypt cost ≥ 10, argon2id at least OWASP `m=19456,t=2` or `m=12288,t=3`, and PBKDF2-HMAC-SHA256 ≥ 600,000 iterations (SHA-512 ≥ 210,000).

See `SECURITY_SCANNER_SPEC.md` §24 Phase 29.
