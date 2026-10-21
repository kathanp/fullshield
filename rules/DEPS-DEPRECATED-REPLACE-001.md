# DEPS-DEPRECATED-REPLACE-001

**Deprecation notice names a replacement that is not a direct dependency.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_DEPRECATED_REPLACE=1`). CWE-1104. Severity info.

The `deprecated` string contains `use <name>` or `replaced by <name>`, and `<name>` matches package-name grammar. A notice without that name, and a replacement that is already a direct dependency, are not findings.

## Remediation

Read the deprecation notice and decide whether to depend on the named package.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 218.
