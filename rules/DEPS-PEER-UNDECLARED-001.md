# DEPS-PEER-UNDECLARED-001

**Production code imports an undeclared peer.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_PEER=1`). CWE-829. Severity medium.

Production code imports a package the lock marks peer: true and the root peerDependencies does not name it. A declared peer, or an import that exists only in a test file, is not a finding.

## Remediation

Add the package to peerDependencies, or remove the import.

See `SECURITY_SCANNER_SPEC.md` phase 123.
