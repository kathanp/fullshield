# SECRET-ENTROPY-001

**High-entropy string assigned to a secret-like name.** CWE-798.

## Remediation

Low confidence. Confirm it is not a live credential.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.

## Rotate

Revoke the old credential in the provider console, issue a new one, and search git history plus config for the old value. Deleting the file does not un-leak a key that was already pushed.

Provider documentation: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
