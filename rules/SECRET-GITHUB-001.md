# SECRET-GITHUB-001

**GitHub token.** CWE-798.

## Checksum

`FULLSHIELD_EXPERIMENTAL_SECRET_CHECK` validates the public CRC-32 suffix for `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, and `github_pat_` tokens. The checksum is CRC-32/IEEE of the token body excluding the last six characters, written as six base62 characters (`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`). A failed check lowers confidence only. It does not raise severity or remove the finding. Other issuers have no checksum logic here.

https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/

## Remediation

Revoke the token and store a new one in env/CI secrets.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
