# DEPS-TARBALL-MANIFEST-001

**Tarball dependencies differ from the packument.** High. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_MANIFEST=1`). CWE-494.

Direct production dependency only. Both `dependencies` objects are present and the key set or a range string differs. Name and version mismatches stay `DEPS-TARBALL-ID-001`. A missing object on either side is not this finding.

## Remediation

Treat the tarball as a swapped manifest.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 182.
