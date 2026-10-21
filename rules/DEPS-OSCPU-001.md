# DEPS-OSCPU-001

**Direct production package excludes this os or cpu.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_OSCPU=1`). CWE-1104. Severity info.

A direct production lock entry has `os` or `cpu` that excludes `process.platform` or `process.arch`. An array that includes the current value, and an empty field, are not this finding. The package is still sent to OSV.

## Remediation

Confirm the install is intentional for this os and cpu. This finding is informational.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 147.
