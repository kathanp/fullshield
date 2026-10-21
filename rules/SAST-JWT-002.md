# SAST-JWT-002

**JWT without expiry or with a short HMAC secret.** Experimental (`FULLSHIELD_EXPERIMENTAL_CRYPTO2=1`). CWE-613. Severity medium.

`jwt.sign` with no `expiresIn` and no `exp`, or an HMAC secret string literal shorter than 32 bytes. `expiresIn: '1h'` with a secret of at least 32 bytes is not a finding.

## Remediation

Set `expiresIn` or `exp`, and use an HMAC secret of at least 32 bytes.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 96.
