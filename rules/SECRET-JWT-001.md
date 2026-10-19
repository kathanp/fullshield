# SECRET-JWT-001

**Hardcoded JWT signing secret.** CWE-798.

## Remediation

Replace the literal with process.env.JWT_SECRET and rotate.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.

## Rotate

Revoke the old credential in the provider console, issue a new one, and search git history plus config for the old value. Deleting the file does not un-leak a key that was already pushed.

Provider documentation: https://www.rfc-editor.org/rfc/rfc7519
