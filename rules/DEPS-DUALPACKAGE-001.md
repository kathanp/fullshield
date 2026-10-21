# DEPS-DUALPACKAGE-001

**CommonJS require of an ESM-only package.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_DUALPACKAGE=1`). CWE-829. Severity medium.

A `require('pkg')` targets a package whose packument `type` is `module` and whose root `exports` has no `require` condition. A `require` condition, an ESM `import`, or a missing packument is not a finding.

## Remediation

Import the package from ESM, or depend on a build that publishes a `require` condition.

See `SECURITY_SCANNER_SPEC.md` Phase 241.
