# SECRET-GOOGLE-001

**Google API key.** CWE-798.

## Remediation

Restrict and rotate the key; do not commit it.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.

## Rotate

Revoke the old credential in the provider console, issue a new one, and search git history plus config for the old value. Deleting the file does not un-leak a key that was already pushed.

Provider documentation: https://cloud.google.com/iam/docs/keys-create-delete
