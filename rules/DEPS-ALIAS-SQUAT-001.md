# DEPS-ALIAS-SQUAT-001

**An npm: alias requests a popular package and installs a different package.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_ALIAS_SQUAT=1`). CWE-494. Severity high.

The requested name is on the popular list and the target name is not that package. An alias whose target is the same popular package is not a finding.

## Remediation

Point the alias at the popular package you meant, or rename the request.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 223.
