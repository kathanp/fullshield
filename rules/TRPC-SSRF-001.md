# TRPC-SSRF-001

**tRPC procedure input reaches a URL.** CWE-918. Requires `FULLSHIELD_EXPERIMENTAL_TRPC=1` and `--modules trpc`.

A procedure `.query` or `.mutation` passes its `input` into `fetch` or another HTTP client. A constant URL is not this finding.

## Remediation

Pass a constant URL, or reject the input before it is requested.
