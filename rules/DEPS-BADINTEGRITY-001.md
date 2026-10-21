# DEPS-BADINTEGRITY-001

**Integrity is not valid algo-base64.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_BADINTEGRITY=1`). CWE-353. Severity high.

integrity is non-empty and is not algo-base64 for sha1, sha256, or sha512, or the base64 does not decode. A well-formed sha512 value is not a finding. A well-formed sha1 value is the weak-hash rule only.

## Remediation

Regenerate the lockfile so integrity is a sha512- base64 value.

See `SECURITY_SCANNER_SPEC.md` phase 118.
