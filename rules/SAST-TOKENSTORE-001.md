# SAST-TOKENSTORE-001

**Token written to localStorage.** Experimental (`FULLSHIELD_EXPERIMENTAL_BROWSER=1`). CWE-922. Severity low.

`localStorage.setItem` whose key name contains `token`, `jwt`, or `accessToken`.

## Remediation

Keep tokens in memory or an httpOnly cookie, not in localStorage.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 101.
