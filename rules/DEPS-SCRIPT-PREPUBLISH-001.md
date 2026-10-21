# DEPS-SCRIPT-PREPUBLISH-001

**Dependency prepublish script.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_PREPUBLISH=1`). CWE-829. Severity high when `scripts.prepublish` is set, medium when only `scripts.prepublishOnly` is set.

The message names the key. Old npm runs `prepublish` on install. No such keys means no finding.

## Remediation

Replace `prepublish` with `prepublishOnly` if the script should run only for an intentional publish.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 192.
