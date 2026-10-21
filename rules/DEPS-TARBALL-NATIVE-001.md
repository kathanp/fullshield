# DEPS-TARBALL-NATIVE-001

**Tarball contains a prebuilt .node file.** Medium. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_NATIVE=1`). CWE-829.

Direct production dependency only. Medium is not a malware claim. A `binding.gyp` with no `.node` file is not this finding. A prebuilt binary could not be reviewed as source.

## Remediation

Review the package before trusting the binary.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 176.
