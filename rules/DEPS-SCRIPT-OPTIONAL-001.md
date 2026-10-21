# DEPS-SCRIPT-OPTIONAL-001

**Optional dependency install script.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_OPTIONAL=1`). CWE-829. Severity medium.

An `optional: true` lock entry with `hasInstallScript`. When the same package is also a transitive production install script, emit only this id.

## Remediation

Review the optional install script. Optional does not mean the script is skipped on every install.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 189.
