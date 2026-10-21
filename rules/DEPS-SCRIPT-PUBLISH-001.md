# DEPS-SCRIPT-PUBLISH-001

**Lifecycle script publishes.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_PUBLISH=1`). CWE-506. Severity high.

A cached lifecycle script contains `npm publish` or `npm whoami`. This is the publish string alone. When `FULLSHIELD_EXPERIMENTAL_VEX=1` and the script also has the `SUPPLY-WORM-001` token-plus-publish combination, this id is not emitted. This lane does not emit `SUPPLY-WORM-001`.

## Remediation

Do not install a package whose install script publishes or queries the npm account.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 200.
