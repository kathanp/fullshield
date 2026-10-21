# DEPS-SCRIPT-ROLLUP-001

**Many production packages have install scripts.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_ROLLUP=1`). CWE-829. Severity info.

One row for the repo when more than 25 production packages have `hasInstallScript`. The count is printed. The threshold is 25 and is not a vulnerability count. Dev-only packages are not counted. A lock with no `hasInstallScript: true` entry emits nothing. Per-package rows stay on `DEPS-SCRIPT-TRANSITIVE-001`.

## Remediation

Review the install scripts. The number is an inventory count.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 207.
