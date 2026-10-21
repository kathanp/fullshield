# DEPS-TAGSPEC-001

**Dist-tag dependency spec.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TAGSPEC=1`). CWE-829. Severity medium.

A direct spec is the bare dist-tag `next`, `beta`, or `canary`, or `name@tag` whose tag contains no digit. Bare `latest` is `DEPS-FLOAT-001`. `1.2.3-beta.1` and `^1.2.3` are not this finding.

## Remediation

Depend on an exact version or a bounded semver range.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 132.
