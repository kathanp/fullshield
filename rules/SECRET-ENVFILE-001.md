# SECRET-ENVFILE-001

**Committed .env file.** CWE-260.

## Remediation

Add .env to .gitignore, rotate every value, keep only .env.example.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.

## Rotate

Revoke the old credential in the provider console, issue a new one, and search git history plus config for the old value. Deleting the file does not un-leak a key that was already pushed.

Provider documentation: https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection
