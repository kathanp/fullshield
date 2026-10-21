# DEPS-TRUSTED-001

**Install script is not listed in trustedDependencies.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TRUSTED=1`). CWE-829. Severity medium.

A committed `.npmrc` sets `ignore-scripts=true`, a direct production dependency's lock entry has `hasInstallScript: true`, and that name is absent from the root `trustedDependencies`. A listed name, and `ignore-scripts` that is not `true`, are not this finding. A missing `hasInstallScript` is not a finding; this rule does not guess from the packument.

## Remediation

Add the package to trustedDependencies after reviewing its install script, or remove the dependency.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 144.
