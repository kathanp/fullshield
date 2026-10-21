# DEPS-SCRIPT-TRANSITIVE-001

**Transitive production dependency install script.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_TRANSITIVE=1`). CWE-829. Severity medium.

One row per transitive production package whose lock entry sets `hasInstallScript`. Direct dependencies are not this id. An optional package that also matches `DEPS-SCRIPT-OPTIONAL-001` is reported only as that id when both flags are on.

## Remediation

Review the transitive install script before installing. Prefer a release with no install script.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 188.
