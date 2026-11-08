# WORKERS-SSRF-001

**WebSocket or Socket.IO message reaches a URL.** CWE-918. Requires `FULLSHIELD_EXPERIMENTAL_WORKERS=1` and `--modules workers`.

A `message` handler passes that argument to `fetch` or an HTTP client. A constant URL is not this finding.

## Remediation

Pass a constant URL, or a field the application checked. Do not pass the raw message as a URL.
