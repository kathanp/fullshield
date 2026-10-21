# DEPS-REG-ENGINES-001

**Dependency engines do not intersect the project.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_ENGINES=1`). CWE-1104. Severity medium.

Project engines.node and the locked version engines.node both parse and do not overlap. An unparseable range is not a finding. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 162.
