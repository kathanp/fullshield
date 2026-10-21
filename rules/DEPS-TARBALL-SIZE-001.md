# DEPS-TARBALL-SIZE-001

**Tarball exceeds the unpack cap.** Info. Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_TARBALL_SIZE=1`). CWE-770.

Direct production dependency only. Unpacked size would exceed 20 MB or the entry count would exceed 2000. Entries past the cap are not extracted. The cap is a limit, not a vulnerability count. A small archive is not this finding.

## Remediation

Inspect the package before raising the cap.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 180.
