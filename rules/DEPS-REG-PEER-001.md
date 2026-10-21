# DEPS-REG-PEER-001

**Packument peer is absent from the lock.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_PEER=1`). CWE-829. Severity medium.

peerDependencies names a package that is not in the lock, unless peerDependenciesMeta marks it optional. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 165.
