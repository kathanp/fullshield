# SAST-REDIRECT-002

**Redirect allowlist uses `includes()`.** CWE-601.

A check such as `url.includes(allowedUrl)` accepts any address that contains an allowlist entry. `startsWith` against a trusted prefix, and a parsed URL compared for equality, are not this finding.

## Remediation

Compare a parsed origin or the full URL for equality. Do not use `String.prototype.includes` as the allowlist check.

See `SECURITY_SCANNER_SPEC.md` §4 and the fixtures under `test/fixtures/`.
