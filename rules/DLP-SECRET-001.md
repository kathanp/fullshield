# DLP-SECRET-001

**Outgoing response contains a secret pattern** (AWS, Stripe, GitHub, Slack, Google, AI, PEM, DB URL). CWE-200. Experimental (`FULLSHIELD_EXPERIMENTAL_DLP=1`).

## Remediation

Do not send credentials in API responses. Rotate anything that leaked. Prefer `shieldGuard({ dlp: { mode: 'monitor' } })` until the benign corpus is measured.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 32 and the fixtures under `test/fixtures/dlp/`.
