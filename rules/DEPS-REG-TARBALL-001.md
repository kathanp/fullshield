# DEPS-REG-TARBALL-001

**Lock tarball URL differs from the registry.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_TARBALL=1`). CWE-494. Severity high.

Both URLs are present, both hosts are registry.npmjs.org, and the URLs differ once the query string is removed. A non-registry lock URL is left to Phase 114. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 149.
