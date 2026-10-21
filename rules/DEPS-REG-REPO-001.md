# DEPS-REG-REPO-001

**Attested source repository changed.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_REPO=1`). CWE-829. Severity medium.

The previous cache recorded an attested source repo and the current attestation names a different repo. First sight and a missing attestation emit nothing. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 156.
