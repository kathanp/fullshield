# SAST-CSRF-001

**Cookie-authenticated POST/PUT/PATCH/DELETE with no CSRF protection and `sameSite` not `strict`/`lax`.** CWE-352.

Experimental (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`).

## Remediation

Use `csurf` / `csrf-csrf` (or equivalent) and set cookie `sameSite` to `lax` or `strict`. Prefer anti-CSRF tokens for cookie sessions.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 29.
