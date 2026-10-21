# DEPS-TARBALL-LIFECYCLE-001

**Tarball lifecycle script hidden by the packument.** High. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_LIFECYCLE=1`). CWE-829.

Direct production dependency only. `preinstall`, `install`, or `postinstall` is present in the tarball and the cached packument `hasInstallScript` is `false`. A missing flag, a `true` flag, or no such scripts is not this finding.

## Remediation

Treat the package as untrusted. The tarball runs an install script the packument marked absent.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 170.
