# SAST-REDOS-001

**Tainted input matched against a regex with nested or overlapping quantifiers.** CWE-1333.

Experimental (`FULLSHIELD_EXPERIMENTAL_CLASSES=1`). Detection is static star-height analysis; user regexes are never executed.

## Remediation

Rewrite the pattern so quantified groups do not contain further quantifiers or overlapping alternations. Prefer a parser or an allow-list over a complex regex.

See `SECURITY_SCANNER_SPEC.md` §24 Phase 29.
