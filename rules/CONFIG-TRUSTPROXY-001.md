# CONFIG-TRUSTPROXY-001

**`trust proxy` set to `true` while IP-based rate limiting is used (spoofable `X-Forwarded-For`).** CWE-290.

Experimental (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`).

## Remediation

Set `trust proxy` to a hop count or subnet, not `true`. Key rate limits on a verified identity, not the raw client IP.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 29.
