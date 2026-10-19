# SECRET-BUNDLE-001

**Secret-shaped value in a client bundle.** CWE-798.

`NEXT_PUBLIC_*` and `VITE_*` values are inlined into the browser. Experimental: `scan --bundle` with `FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1`.

## Remediation

Do not prefix secrets with `NEXT_PUBLIC_` or `VITE_`. Keep credentials server-side. Rotate any key that was bundled.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 30.

## Rotate

Revoke the old credential in the provider console, issue a new one, and search git history plus config for the old value. Deleting the file does not un-leak a key that was already pushed.

Provider documentation: https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions
