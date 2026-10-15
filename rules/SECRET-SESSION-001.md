# SECRET-SESSION-001

**Hardcoded `express-session` `secret` string.** CWE-798.

## Remediation

Load the session secret from the environment (for example `process.env.SESSION_SECRET`) and rotate any value that was committed.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
