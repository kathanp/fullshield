# DEPS-ENGINE-STRICT-001

**engine-strict is false while engines.node is set.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_ENGINE_STRICT=1`). CWE-693. Severity info.

`engines.node` is set and a committed `.npmrc` sets `engine-strict=false`. `engine-strict=true`, and a manifest with no engines field, are not this finding.

## Remediation

Set engine-strict=true so installs honor engines.node.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 143.
