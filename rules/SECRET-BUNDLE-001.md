# SECRET-BUNDLE-001

**Secret-shaped value in a client bundle.** CWE-798.

`NEXT_PUBLIC_*` and `VITE_*` values are inlined into the browser. Experimental: `scan --bundle` with `FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1`.

## Remediation

Do not prefix secrets with `NEXT_PUBLIC_` or `VITE_`. Keep credentials server-side. Rotate any key that was bundled.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 30.
