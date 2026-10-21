# DEPS-NPMALIAS-001

**npm alias name does not match the target.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_ALIAS=1`). CWE-829. Severity medium.

A lock key or manifest spec uses npm: and the requested name differs from the target name. The finding is on the requested name and records the target name@version. npm:same-name@1.2.3 is not a finding.

## Remediation

Depend on the target package directly.

See `SECURITY_SCANNER_SPEC.md` phase 121.
