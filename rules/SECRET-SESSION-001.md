# SECRET-SESSION-001

**Hardcoded `express-session` `secret` string.** CWE-798.

## Remediation

Load the session secret from the environment (for example `process.env.SESSION_SECRET`) and rotate any value that was committed.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.

## Rotate

Revoke the old credential in the provider console, issue a new one, and search git history plus config for the old value. Deleting the file does not un-leak a key that was already pushed.

Provider documentation: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
