# DEPS-SCRIPT-MULTI-001

**Several lifecycle scripts.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_MULTI=1`). CWE-829. Severity info.

A cached package has two or more of `preinstall`, `install`, and `postinstall`. Exactly one is not this finding. Info is an inventory signal, not a claim that the package is malicious.

## Remediation

Read each lifecycle script.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 203.
