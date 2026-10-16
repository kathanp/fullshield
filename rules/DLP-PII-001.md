# DLP-PII-001

**Outgoing response contains bulk emails on a route that normally returns one.** CWE-359. Experimental (`FULLSHIELD_EXPERIMENTAL_DLP=1`).

## Remediation

Scope list/export endpoints. Do not dump address books from a single-user route.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 32 and the fixtures under `test/fixtures/dlp/`.
