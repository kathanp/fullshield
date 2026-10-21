# DEPS-REG-TIME-001

**Packument time is missing, unparseable, or in the future.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_TIME=1`). CWE-345. Severity medium.

time[version] is missing, does not parse, or is after the scan clock. A past timestamp, including a young one, is not this finding. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 158.
