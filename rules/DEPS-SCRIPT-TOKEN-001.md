# DEPS-SCRIPT-TOKEN-001

**Lifecycle script reads an npm token.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SCRIPT_TOKEN=1`). CWE-522. Severity critical.

A cached lifecycle script contains `NPM_TOKEN`, `NODE_AUTH_TOKEN`, or `npm_config__auth`. This lane cannot see phase 173 findings, so it reports the script text it can read. The script is not executed and token values are not printed.

## Remediation

Do not install the package. Rotate npm tokens on machines that already installed it.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 199.
