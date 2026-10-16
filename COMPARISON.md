# Comparison

Human review of the mapping is required before this file is linked from the README.
Numbers below are only filled when the tool was executed in this environment.

## Tool versions

Not executed in this commit. `node bench/compare.mjs` records Semgrep, OSV-Scanner, and npm versions when they are installed, and writes "not installed" when they are not. It does not invent true-positive or miss counts.

## Mapping

| tool | pattern | class |
|---|---|---|
| semgrep | javascript.lang.security.audit.sqli | sqli |
| semgrep | javascript.lang.security.audit.command | cmdi |
| semgrep | javascript.lang.security.audit.path | path |
| semgrep | javascript.lang.security.audit.xss | xss |
| osv-scanner | CVE- | deps |
| osv-scanner | GHSA- | deps |
| npm-audit | advisory | deps |

Unmapped rules are counted separately. They are not assigned a FullShield class.

## Results

Not executed. No true-positive, miss, or alert counts are recorded.
