# SAST-CSRF-001

**Cookie-authenticated POST/PUT/PATCH/DELETE with no CSRF protection and `sameSite` not `strict`/`lax`.** CWE-352.

Experimental (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`).

## Remediation

Use `csurf`, `csrf-csrf`, `csrf-sync`, `lusca`, or `@fastify/csrf-protection`, including `app.use` in `app.js` when routes live in another file. Set cookie `sameSite` to `lax` or `strict`.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 29.
