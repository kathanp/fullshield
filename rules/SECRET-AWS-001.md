# SECRET-AWS-001

**AWS access key.** CWE-798.

## Remediation

Rotate the key. Load it from the environment. Removing it from the file is not enough — it stays in git history.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.

## Rotate

Revoke the old credential in the provider console, issue a new one, and search git history plus config for the old value. Deleting the file does not un-leak a key that was already pushed.

Provider documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
