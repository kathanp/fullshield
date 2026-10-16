# SAST-COOKIE-001

**Session/auth cookies without `httpOnly`, `secure`, or `sameSite`.** A hardcoded `express-session` secret is `SECRET-SESSION-001` only, so this rule does not add a second finding. CWE-614 / CWE-1004.

Experimental (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`).

## Remediation

Set `httpOnly: true`, `secure: true`, and `sameSite: 'lax'` or `'strict'`. Load the session secret from the environment and rotate it.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 29.
