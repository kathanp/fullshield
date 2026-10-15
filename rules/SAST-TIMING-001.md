# SAST-TIMING-001

**Secrets, tokens, or HMACs compared with `===` / `==` instead of `crypto.timingSafeEqual`.** CWE-208.

Experimental (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`).

## Remediation

Compare MACs and tokens with `crypto.timingSafeEqual` on equal-length Buffers.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 29.
