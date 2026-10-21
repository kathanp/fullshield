# DEPS-REG-DEPRECATED-001

**Registry deprecation is missing from the lock.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_DEPRECATED=1`). CWE-1104. Severity info.

The packument version has a non-empty deprecated string and the lock entry does not. The same string on the lock stays DEPS-DEPRECATED-001 only. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 150.
