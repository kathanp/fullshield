# DEPS-FLOAT-002

**Direct production spec with no upper bound.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_FLOAT=1`). CWE-829. Severity low.

A direct production spec (`dependencies` or `optionalDependencies`) is `>=` or `>` and has no `<` upper bound. A caret, tilde, or exact version is not this finding.

## Remediation

Add an upper bound, or switch to a caret, tilde, or exact version.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 128.
