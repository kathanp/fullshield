# DEPS-SCRIPT-DEV-001

**Development-only dependency install script.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_DEV=1`). CWE-829. Severity info.

A `dev: true` lock entry with `hasInstallScript` that is not also required by a non-dev package. A production install script is not this id.

## Remediation

Confirm the package stays dev-only. Read the install script before a development install.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 190.
