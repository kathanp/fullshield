# DEPS-LINKDEP-001

**file: or link: dependency.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_LINKDEP=1`). CWE-829. Severity medium.

resolved or a manifest spec is file: or link:. The message includes the path. Severity is high, same id, when the path contains .. and resolves outside the repo root. A registry tarball is not a finding.

## Remediation

Prefer a registry release. Keep file: and link: paths inside the repo.

See `SECURITY_SCANNER_SPEC.md` phase 119.
