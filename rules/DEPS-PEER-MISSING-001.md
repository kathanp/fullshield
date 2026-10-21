# DEPS-PEER-MISSING-001

**Non-optional peer missing from the lock.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_PEER=1`). CWE-829. Severity medium.

A `peerDependencies` entry is not optional in `peerDependenciesMeta` and no copy of that package is in the lock. An optional peer is not a finding, whether or not it is installed. A peer that is present is not a finding. This does not change `DEPS-PEER-UNDECLARED-001`.

## Remediation

Add the peer to the root dependencies so the lock installs it, or declare the peer optional.

See `SECURITY_SCANNER_SPEC.md` Phase 230.
