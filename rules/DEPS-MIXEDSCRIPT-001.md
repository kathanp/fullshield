# DEPS-MIXEDSCRIPT-001

**Dependency name mixes Latin with Cyrillic or Greek.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_MIXEDSCRIPT=1`). CWE-1007. Severity high.

The name contains both a Latin letter and a Cyrillic or Greek letter. Latin-only names, Cyrillic-only names that are not homoglyphs, and names already reported as homoglyphs are not findings.

## Remediation

Use a package name written in one script.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 211.
