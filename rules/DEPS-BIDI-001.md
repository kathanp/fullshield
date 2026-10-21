# DEPS-BIDI-001

**Dependency name contains a bidi or zero-width character.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_BIDI=1`). CWE-1007. Severity critical.

The name contains a character in U+202A–U+202E, U+2066–U+2069, or U+200B–U+200F. An ASCII name is not a finding.

## Remediation

Remove the dependency and use an ASCII package name.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 210.
