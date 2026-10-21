# DEPS-NAME-LENGTH-001

**Dependency name is empty or longer than 214 characters.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_NAME_LENGTH=1`). CWE-1284. Severity high.

npm's documented package name limit is 214 characters. A normal name is not a finding.

## Remediation

Use a package name within npm's 214 character limit.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 220.
