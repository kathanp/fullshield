# DEPS-REG-SUBJECT-001

**Attestation subject version is not the locked version.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_SUBJECT=1`). CWE-345. Severity high.

An attestation subject version is present and it is not the locked version. No subject field is not a finding. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 157.
