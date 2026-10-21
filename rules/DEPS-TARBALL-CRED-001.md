# DEPS-TARBALL-CRED-001

**Lifecycle script reads credentials.** Critical. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_CRED=1`). CWE-522.

Direct production dependency only. A `preinstall`, `install`, or `postinstall` string contains `.npmrc`, `.ssh`, `.aws`, `.git-credentials`, `NPM_TOKEN`, `NODE_AUTH_TOKEN`, or `npm_config__auth`. The same strings under `test/` are not this finding. No second signal is required.

## Remediation

Do not install this package.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 173.
