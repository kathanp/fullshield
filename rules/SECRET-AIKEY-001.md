# SECRET-AIKEY-001

**OpenAI/Anthropic-style API key.** CWE-798.

## Remediation

Rotate and load from env. Never send scanned code to an AI provider without consent.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.

## Rotate

Revoke the old credential in the provider console, issue a new one, and search git history plus config for the old value. Deleting the file does not un-leak a key that was already pushed.

Provider documentation: https://platform.openai.com/docs/api-reference/authentication

Anthropic-style keys: https://docs.anthropic.com/en/api/getting-started
