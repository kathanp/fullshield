# DEPS-NOINTEGRITY-001

**Registry tarball has no integrity.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_NOINTEGRITY=1`). CWE-353. Severity high.

resolved is an https registry.npmjs.org URL and integrity is missing or empty. link: and file: rows are not this finding.

## Remediation

Regenerate the lockfile so the entry has a sha512 integrity.

See `SECURITY_SCANNER_SPEC.md` phase 116.
