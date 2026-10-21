# DEPS-REG-UNPUBLISHED-001

**Locked version is absent from the packument.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_UNPUBLISHED=1`). CWE-829. Severity critical.

The cached packument has a versions object and does not list the locked version. A missing cache file is not unpublished. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 151.
