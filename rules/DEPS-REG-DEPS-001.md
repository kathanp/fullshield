# DEPS-REG-DEPS-001

**Locked dependency misses the packument range.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_DEPS=1`). CWE-1104. Severity medium.

versions[version].dependencies[name] is a range the semver helper understands and the locked version of name does not satisfy it. An unparseable range is not a finding. The lock is not rewritten. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 164.
