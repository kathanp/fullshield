# DEPS-TARBALL-NET-001

**Lifecycle script contains a network token.** High. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_NET=1`). CWE-829.

Direct production dependency only. A `preinstall`, `install`, or `postinstall` string contains `http://`, `https://`, `fetch(`, or `dns`. Fixture hosts are `example.invalid`.

## Remediation

Remove the install script or pin a release whose lifecycle script does not fetch remote code.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 171.
