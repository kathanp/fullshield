# DEPS-REG-NPMUSER-001

**Publisher is not a maintainer.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_NPMUSER=1`). CWE-829. Severity medium.

_npmUser.name is a non-empty string, maintainers is a non-empty array, and the name is not in it. A missing _npmUser is not a finding. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 152.
