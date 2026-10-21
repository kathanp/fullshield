# DEPS-REG-SIGNATURES-001

**Registry signatures are an empty array.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_SIGNATURES=1`). CWE-345. Severity info.

dist.signatures is present and empty. A non-empty array, or a version with no signatures key, is not a finding. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 161.
