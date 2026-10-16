# DLP-INTERNAL-001

**Outgoing response contains an internal IP or hostname.** CWE-200. Experimental (`FULLSHIELD_EXPERIMENTAL_DLP=1`).

## Remediation

Do not expose RFC1918 / loopback / `*.internal` addresses in client responses.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 32 and the fixtures under `test/fixtures/dlp/`.
