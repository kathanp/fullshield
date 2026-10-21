# DEPS-REG-MAINTAINER-001

**Maintainer set changed since the previous cache.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_MAINTAINER=1`). CWE-829. Severity medium.

previous.maintainers differs from the sorted maintainers[].name set. The first cache sight emits nothing. This is not SUPPLY-PROVENANCE-001. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 153.
