# DEPS-TARBALL-HIDDEN-001

**Tarball path uses a bidi override or a hidden non-latin segment.** Medium. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_HIDDEN=1`). CWE-451.

Direct production dependency only. A segment contains a bidi override or isolate (U+202A–U+202E, U+2066–U+2069), or a segment other than `.npmignore`, `.gitignore`, or `.github` starts with `.` and contains a non-latin letter. `.gitignore` and `lib/index.js` are not this finding.

## Remediation

Reject the archive.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 178.
