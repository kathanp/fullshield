# DEPS-GRAPH-OPTIONAL-001

**Missing optional dependency.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_OPTIONAL=1`). CWE-829. Severity info.

An `optionalDependencies` entry in the lock or root manifest has no installed copy in the lock. The finding names that missing package. A missing optional dependency does not mark its parent `not-imported`. The optional package being present is not a finding.

## Remediation

Install the optional package, or remove it from `optionalDependencies`.

See `SECURITY_SCANNER_SPEC.md` Phase 229.
