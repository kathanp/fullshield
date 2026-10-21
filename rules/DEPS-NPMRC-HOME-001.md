# DEPS-NPMRC-HOME-001

**Home .npmrc registry is not registry.npmjs.org.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_NPMRC_HOME=1`). CWE-494. Severity medium.

This is the `scan --include-home` check. The real user home is not read. The test hook is `FULLSHIELD_NPM_HOME`: when that variable is set, this rule reads `$FULLSHIELD_NPM_HOME/.npmrc` and nowhere else outside the project. It also reads a scan file whose path is exactly `home/.npmrc`. Without the variable and without that path, no home file is opened. The default host `registry.npmjs.org` is not a finding. Token values are not printed. A token in `~/.npmrc` is out of scope (the file is not committed).

## Remediation

Point the home registry at https://registry.npmjs.org/.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 139.
