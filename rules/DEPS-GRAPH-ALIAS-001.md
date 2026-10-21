# DEPS-GRAPH-ALIAS-001

**npm alias edge.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_GRAPH_ALIAS=1`). CWE-829. Severity info.

A dependency spec uses the `npm:` protocol, or a lockfile path name differs from the entry `name`. The finding records `alias → target`. A normal version range is not a finding. Advisory rows stay on the target version.

## Remediation

Confirm the alias is meant to install the target package.

See `SECURITY_SCANNER_SPEC.md` Phase 231.
