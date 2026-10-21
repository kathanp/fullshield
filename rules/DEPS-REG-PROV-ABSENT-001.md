# DEPS-REG-PROV-ABSENT-001

**Direct production dependency has no attestation.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_PROV_ABSENT=1`). CWE-494. Severity info.

A direct production version has no dist.attestations and no dist.signatures. This is not a malicious-package claim and does not replace SUPPLY-PROV-001. A cache miss emits nothing. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 154.
