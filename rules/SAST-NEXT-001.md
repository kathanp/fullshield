# SAST-NEXT-001

**Server action writes without an auth check.** Experimental (`FULLSHIELD_EXPERIMENTAL_NEXT=1`). CWE-306. Severity medium. Confidence low.

An exported `'use server'` function writes through a data sink and the file does not call `auth()`, `getServerSession`, `currentUser`, or `cookies()`.

## Remediation

Check the session inside the server action before writing.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 103.
