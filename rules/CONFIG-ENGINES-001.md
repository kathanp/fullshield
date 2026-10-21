# CONFIG-ENGINES-001

**engines.node does not include the pinned Node version.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_ENGINES=1`). CWE-1104. Severity medium. Module `config`.

`.nvmrc` or `.node-version` pins `MAJOR.MINOR.PATCH` and `engines.node` does not include it. The comparison uses the existing semver helper. If that helper cannot parse the range, this rule emits nothing. A pin the range includes, a repository with no pin file, and a pin that is not `MAJOR.MINOR.PATCH` (for example `lts/iron`) are not findings. A pin with no `engines.node` string does not include that version.

## Remediation

Widen engines.node to include the pinned version, or change the pin file.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 142.
