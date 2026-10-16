# DLP-STACK-001

**Outgoing response contains a stack trace.** CWE-209. Experimental (`FULLSHIELD_EXPERIMENTAL_DLP=1`).

## Remediation

Log stacks server-side. Return a generic error body to clients.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 32 and the fixtures under `test/fixtures/dlp/`.
