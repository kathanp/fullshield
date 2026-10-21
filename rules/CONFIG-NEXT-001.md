# CONFIG-NEXT-001

**Auth enforced only in middleware.** Experimental (`FULLSHIELD_EXPERIMENTAL_NEXT=1`). CWE-306. Severity info. One finding per app.

`middleware.ts` calls auth and its matcher is present, while a route under `app/` or `pages/` does not. The message names the 2025 middleware-bypass class and says to enforce auth in the handler.

## Remediation

Enforce authentication in the route handler, not only in middleware.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 103.
