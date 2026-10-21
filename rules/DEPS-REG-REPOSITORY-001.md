# DEPS-REG-REPOSITORY-001

**Package repository host changed.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_REPOSITORY=1`). CWE-829. Severity info.

A previous cache had a repository host and the current packument host differs, or the repository field disappeared. First sight emits nothing. The repository is not fetched. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 167.
