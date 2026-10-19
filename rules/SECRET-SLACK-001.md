# SECRET-SLACK-001

**Slack token.** CWE-798.

## Remediation

Revoke the token in Slack and load a replacement from env.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.

## Rotate

Revoke the old credential in the provider console, issue a new one, and search git history plus config for the old value. Deleting the file does not un-leak a key that was already pushed.

Provider documentation: https://api.slack.com/authentication/token-types
