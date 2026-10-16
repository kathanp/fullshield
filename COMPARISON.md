# Comparison

Human review of the mapping is required before this file is linked from the README.
Counts below are from one local run. They are not a recall claim.

## Tool versions

- semgrep: `1.180.0`
- osv-scanner: `osv-scanner version: 2.7.0`
- npm: `11.19.0`

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

### nodegoat

- semgrep findings: 10; unmapped: 10; mapped: {}
- semgrep example check_id: javascript.lang.security.audit.code-string-concat.code-string-concat
- osv-scanner vulnerability records: 206
- npm audit total: 149

### juice-shop

- semgrep findings: 18; unmapped: 18; mapped: {}
- semgrep example check_id: javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
- osv-scanner: not executed (No package sources found, --help for usage information.)
- npm audit total: 46

### dvna

- semgrep findings: 11; unmapped: 11; mapped: {}
- semgrep example check_id: javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
- osv-scanner: not executed (No package sources found, --help for usage information.)
- npm audit total: 0

### goof

- semgrep findings: 5; unmapped: 5; mapped: {}
- semgrep example check_id: javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-domain
- osv-scanner vulnerability records: 268
- npm audit total: 152

### vulnerable-node

- semgrep findings: 12; unmapped: 12; mapped: {}
- semgrep example check_id: javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal
- osv-scanner vulnerability records: 5
- npm audit total: 3

FullShield default-scan counts for these apps stay in BENCHMARK.md. This file does not retune rules.
Commercial scanners were not executed.
