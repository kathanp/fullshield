# DEPS-OVERRIDE-ALIAS-001

**Override installs a different package name.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_OVERRIDE_ALIAS=1`). CWE-829. Severity high.

An override value is `npm:other@version` and `other` is not the overridden package name. An exact version is not this finding. This row is the manifest override only.

## Remediation

Override to the same package name, or remove the npm: alias.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 135.
