# SAST-LOGLEAK-001

**Secret written to a log.** Experimental (`FULLSHIELD_EXPERIMENTAL_LOGLEAK=1`). CWE-532. Severity medium.

`console`, winston, pino, bunyan, debug, or morgan logs `req.headers.authorization`, `req.headers.cookie`, the whole `req.body` on an auth route, or an identifier whose camelCase segments are `password`, `passwd`, `secret`, `token`, `apiKey`, or `authorization`. `tokenCount` is not a finding. A pino or winston `redact` list that covers the path clears that path. `req.body` on a non-auth route is not a finding.

## Remediation

Do not log credentials. Redact the path when the logger supports it.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 98.
