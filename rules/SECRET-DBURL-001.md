# SECRET-DBURL-001

**Database URL with an inline password.** CWE-798.

## Remediation

Angle-bracket placeholders are ignored. Real passwords must be rotated and moved to env.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.

## Rotate

Revoke the old credential in the provider console, issue a new one, and search git history plus config for the old value. Deleting the file does not un-leak a key that was already pushed.

Provider documentation: https://www.postgresql.org/docs/current/auth-password.html
