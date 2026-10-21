# DEPS-REG-BIN-001

**Packument bin path escapes the package.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_BIN=1`). CWE-22. Severity high.

A bin target contains a .. segment, is absolute, or contains a backslash parent segment. bin/cli.js is not a finding. This is the path, not a name collision. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 166.
