# DEPS-TARBALL-PATH-001

**Tarball entry or bin path escapes the package.** Critical. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_PATH=1`). CWE-22.

Direct production dependency only. An entry name, after `\\` is normalized to `/`, is absolute or contains a `..` segment. The extractor skips that entry. This check runs when this flag is on even if later tarball flags are off. A normal `package/lib/index.js` is not this finding.

## Remediation

Do not extract the entry.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 179.
