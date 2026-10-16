# DLP-CARD-001

**Outgoing response contains a Luhn-valid card number.** CWE-359. Experimental (`FULLSHIELD_EXPERIMENTAL_DLP=1`).

## Remediation

Never return full PANs. Store tokens; show only the last four digits if needed.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 32 and the fixtures under `test/fixtures/dlp/`.
