# DEPS-FILESPEC-001

**file: or link: spec in package.json.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_FILESPEC=1`). CWE-829. Severity medium.

A direct spec uses `file:` or `link:`. A semver range is not this finding. This id is the manifest row for that spec.

## Remediation

Depend on a published registry version instead of a local path.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 130.
