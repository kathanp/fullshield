# DEPS-NAME-CASE-001

**Two locked package names differ only by ASCII case.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_NAME_CASE=1`). CWE-178. Severity high.

One row names both packages. Distinct names are not a finding.

## Remediation

Keep one spelling. npm package names are lowercase.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 221.
