# DEPS-COREPACK-001

**packageManager has no Corepack integrity hash.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_COREPACK=1`). CWE-353. Severity info.

`packageManager` is `name@exact` and has no `+sha512.` suffix, and `devEngines.packageManager` has no hash. A field that already contains `+sha512.` is not this finding. This check does not download the package-manager tarball.

## Remediation

Append the Corepack +sha512. hash, or set devEngines.packageManager to a hashed version.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 141.
