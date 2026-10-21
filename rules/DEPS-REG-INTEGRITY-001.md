# DEPS-REG-INTEGRITY-001

**Lock integrity differs from the registry packument.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_INTEGRITY=1`). CWE-353. Severity critical.

Both the lock integrity and versions[version].dist.integrity are present and not equal. A missing value on either side is not a finding. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 148.
