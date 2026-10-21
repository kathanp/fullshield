# DEPS-REG-AGE-001

**Transitive production release is inside the age window.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_REG_TRANSITIVE_AGE=1`). CWE-1104. Severity low.

A transitive production package time[version] is younger than deps.minReleaseAgeHours (default 72). Direct dependencies are not reported here. Missing time is not a finding. FullShield reads the registry cache only and does not contact the network.

## Remediation

Compare the lock with the cached packument and decide whether to keep the dependency. FullShield does not name a replacement package and does not rewrite the lock.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 159.
