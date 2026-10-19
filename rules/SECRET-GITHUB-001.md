# SECRET-GITHUB-001

**GitHub token.** CWE-798.

## Remediation

Revoke the token and store a new one in env/CI secrets.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.

## Rotate

Revoke the old credential in the provider console, issue a new one, and search git history plus config for the old value. Deleting the file does not un-leak a key that was already pushed.

Provider documentation: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository

Token checksum (Phase 82, flag `FULLSHIELD_EXPERIMENTAL_SECRET_CHECK`): the last 6 characters of a `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` / `github_pat_` token are a CRC-32 of the preceding body, base62-encoded. Documented at https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/. A failed checksum lowers confidence. It does not delete the finding. npm tokens have no checksum here.
