# DEPS-WEAKINTEGRITY-001

**Integrity uses sha1 or sha256.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_WEAKINTEGRITY=1`). CWE-328. Severity medium.

integrity uses sha1 or sha256. The registry algorithm is sha512. A missing integrity is not this finding. A weak but well-formed hash is not also reported as a grammar failure.

## Remediation

Regenerate the lockfile so integrity starts with sha512-.

See `SECURITY_SCANNER_SPEC.md` phase 117.
