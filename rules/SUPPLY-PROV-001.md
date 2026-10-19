# SUPPLY-PROV-001

**Provenance or publisher change.** CWE-494. Experimental (`FULLSHIELD_EXPERIMENTAL_PROVENANCE=1`). Severity is medium at most.

Signals are provenance regression, a new publishing user, or a release younger than the cooldown. Missing registry data stays unknown. These signals do not mean the package is malicious.

## Remediation

Compare the version with the previous publisher and attestation on registry.npmjs.org. `DEPS-MALICIOUS-001` still comes only from an OSV `MAL-` advisory.
