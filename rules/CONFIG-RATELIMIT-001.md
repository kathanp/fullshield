# CONFIG-RATELIMIT-001

**Login/signup route with no rate limiter.** CWE-307.

## Remediation

Apply express-rate-limit (or similar) to auth routes.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
