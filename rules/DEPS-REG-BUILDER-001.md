# DEPS-REG-BUILDER-001

**Attestation builder is not in the allowlist.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_BUILDER=1`). CWE-494. Severity medium.

dist.attestations is present and a builder identity read from that object is not in models/npm-builders.json. No attestation is not this finding. The allowlist is not downloaded. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 155.
