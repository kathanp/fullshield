# DEPS-REG-DRIFT-001

**A newer packument version satisfies the manifest range.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_DRIFT=1`). CWE-1104. Severity info.

The manifest range parses, a greater packument version satisfies it, and the locked version is smaller. This is drift, not an advisory. The named version is a packument key. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 163.
