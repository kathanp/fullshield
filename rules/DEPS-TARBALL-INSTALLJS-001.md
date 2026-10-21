# DEPS-TARBALL-INSTALLJS-001

**Loose install.js without a matching scripts key.** Medium. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_INSTALLJS=1`). CWE-829.

Direct production dependency only. The archive contains `package/install.js`, `package/preinstall.js`, or `package/postinstall.js` and `scripts` has no matching key. A declared key, or no such file, is not this finding.

## Remediation

Remove the loose file or declare the matching scripts key.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 183.
