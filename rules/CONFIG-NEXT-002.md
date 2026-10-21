# CONFIG-NEXT-002

**Next.js image remote pattern is unrestricted.** Experimental (`FULLSHIELD_EXPERIMENTAL_NEXT=1`). CWE-942. Severity medium.

`images.remotePatterns` uses hostname `**`, or `images.domains` includes `*`.

## Remediation

List explicit image hostnames.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 103.
