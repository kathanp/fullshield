# SAST-RSA-001

**Weak key generation.** Experimental (`FULLSHIELD_EXPERIMENTAL_CRYPTO2=1`). CWE-326. Severity medium.

`generateKeyPair('rsa', { modulusLength })` below 2048, or `ec` with a `secp192*` curve.

## Remediation

Use RSA 2048 or larger, or a modern curve.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 96.
