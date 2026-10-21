# DEPS-SCRIPT-BIN-001

**Bin path is the install script.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_BIN=1`). CWE-829. Severity medium.

A lock `bin` target equals the path named by `scripts.install` or `scripts.preinstall` after a leading `node ` is removed. Different paths are not this finding.

## Remediation

Confirm the command you run is not the package install script.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 204.
