# AGENTS-SYSTEM-001

**Untrusted input in a system message.** CWE-1426. Requires `FULLSHIELD_EXPERIMENTAL_AGENTS=1` and `--modules agents`.

Request body, query, params, headers, or cookies reach a message whose role is `system`. A literal system prompt is not this finding. User text kept in the user role is not this finding.

## Remediation

Keep user text in the user role. Do not concatenate it into the system message.
