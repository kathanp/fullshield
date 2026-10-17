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
| semgrep | sequelize-injection | sqli |
| semgrep | sql-injection | sqli |
| semgrep | audit.sqli | sqli |
| semgrep | nosql | nosqli |
| semgrep | mongodb | nosqli |
| semgrep | command-injection | cmdi |
| semgrep | child-process | cmdi |
| semgrep | audit.command | cmdi |
| semgrep | path-join-resolve-traversal | path |
| semgrep | path-traversal | path |
| semgrep | audit.path | path |
| semgrep | ssrf | ssrf |
| semgrep | open-redirect | redirect |
| semgrep | audit.redirect | redirect |
| semgrep | xss | xss |
| semgrep | code-string-concat | eval |
| semgrep | eval-detected | eval |
| semgrep | detect-eval | eval |
| semgrep | jwt | jwt |
| semgrep | weak-crypto | crypto |
| semgrep | md5 | crypto |
| semgrep | prototype-pollution | proto |
| semgrep | hardcoded-secret | secrets |
| semgrep | hardcoded-password | secrets |
| semgrep | private-key | secrets |
| semgrep | detected-private-key | secrets |
| semgrep | cookie-settings | config |
| semgrep | helmet | config |
| semgrep | cors | config |
| osv-scanner | CVE- | deps |
| osv-scanner | GHSA- | deps |
| npm-audit | advisory | deps |

Unmapped rules are counted separately. They are not assigned a FullShield class.

## Results

### nodegoat

- lockfile: package-lock.json
- semgrep findings: 10; unmapped: 0; mapped: {"eval":3,"redirect":1,"config":6}
- semgrep example check_id: javascript.lang.security.audit.code-string-concat.code-string-concat
- osv-scanner vulnerability records: 206
- npm audit total: 149
- FullShield findings in this run: 256 (unreviewed)
- Class overlap vs ground truth (class + file + line ±3). Not reviewed. Not a recall claim.
- ground truth reviewed: false
- config: FullShield only 1; Semgrep only 0; both 0; neither 0
- deps: FullShield only 1; Semgrep only 0; both 0; neither 0
- eval: FullShield only 0; Semgrep only 0; both 1; neither 0
- nosqli: FullShield only 1; Semgrep only 0; both 0; neither 0
- redirect: FullShield only 0; Semgrep only 0; both 1; neither 0
- ssrf: FullShield only 1; Semgrep only 0; both 0; neither 0
- xss: FullShield only 0; Semgrep only 0; both 0; neither 1

### juice-shop

- lockfile: none at this pin.
- semgrep findings: 18; unmapped: 9; mapped: {"sqli":6,"jwt":1,"redirect":1,"eval":1}
- semgrep example check_id: javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
- osv-scanner: not executed (No package sources found, --help for usage information.)
- npm audit total: 46
- FullShield findings in this run: 105 (unreviewed)
- Class overlap vs ground truth (class + file + line ±3). Not reviewed. Not a recall claim.
- ground truth reviewed: false
- config: FullShield only 2; Semgrep only 0; both 0; neither 0
- deps: FullShield only 1; Semgrep only 0; both 0; neither 0
- eval: FullShield only 0; Semgrep only 0; both 1; neither 0
- nosqli: FullShield only 3; Semgrep only 0; both 0; neither 0
- redirect: FullShield only 0; Semgrep only 0; both 1; neither 1
- sqli: FullShield only 0; Semgrep only 0; both 2; neither 0
- xss: FullShield only 0; Semgrep only 0; both 0; neither 1

### dvna

- lockfile: none at this pin.
- semgrep findings: 11; unmapped: 2; mapped: {"sqli":1,"redirect":1,"config":6,"secrets":1}
- semgrep example check_id: javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
- osv-scanner: not executed (No package sources found, --help for usage information.)
- npm audit total: 0
- FullShield findings in this run: 23 (unreviewed)
- Class overlap vs ground truth (class + file + line ±3). Not reviewed. Not a recall claim.
- ground truth reviewed: false
- cmdi: FullShield only 1; Semgrep only 0; both 0; neither 0
- config: FullShield only 0; Semgrep only 0; both 0; neither 1
- crypto: FullShield only 1; Semgrep only 0; both 0; neither 0
- deps: FullShield only 1; Semgrep only 0; both 0; neither 0
- eval: FullShield only 1; Semgrep only 0; both 0; neither 0
- redirect: FullShield only 0; Semgrep only 0; both 1; neither 0
- secrets: FullShield only 0; Semgrep only 0; both 1; neither 0
- sqli: FullShield only 0; Semgrep only 0; both 1; neither 0
- xss: FullShield only 2; Semgrep only 0; both 0; neither 0

### goof

- lockfile: package-lock.json
- semgrep findings: 5; unmapped: 0; mapped: {"config":4,"secrets":1}
- semgrep example check_id: javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-domain
- osv-scanner vulnerability records: 268
- npm audit total: 152
- FullShield findings in this run: 271 (unreviewed)
- Class overlap vs ground truth (class + file + line ±3). Not reviewed. Not a recall claim.
- ground truth reviewed: false
- cmdi: FullShield only 1; Semgrep only 0; both 0; neither 0
- config: FullShield only 1; Semgrep only 0; both 0; neither 0
- deps: FullShield only 2; Semgrep only 0; both 0; neither 0
- nosqli: FullShield only 1; Semgrep only 0; both 0; neither 0
- path: FullShield only 1; Semgrep only 0; both 0; neither 0
- proto: FullShield only 1; Semgrep only 0; both 0; neither 0
- redirect: FullShield only 1; Semgrep only 0; both 0; neither 0
- secrets: FullShield only 0; Semgrep only 0; both 1; neither 0
- xss: FullShield only 2; Semgrep only 0; both 0; neither 0

### vulnerable-node

- lockfile: package-lock.json
- semgrep findings: 12; unmapped: 2; mapped: {"path":2,"xss":3,"jwt":1,"config":4}
- semgrep example check_id: javascript.express.security.audit.express-path-join-resolve-traversal.express-path-join-resolve-traversal
- osv-scanner vulnerability records: 5
- npm audit total: 3
- FullShield findings in this run: 61 (unreviewed)
- Class overlap vs ground truth (class + file + line ±3). Not reviewed. Not a recall claim.
- ground truth reviewed: false
- cmdi: FullShield only 1; Semgrep only 0; both 0; neither 0
- config: FullShield only 0; Semgrep only 0; both 0; neither 1
- jwt: FullShield only 1; Semgrep only 0; both 0; neither 0
- nosqli: FullShield only 0; Semgrep only 0; both 0; neither 2
- path: FullShield only 0; Semgrep only 0; both 1; neither 0
- proto: FullShield only 1; Semgrep only 0; both 0; neither 0
- sqli: FullShield only 3; Semgrep only 0; both 0; neither 0
- ssrf: FullShield only 1; Semgrep only 0; both 0; neither 0
- xss: FullShield only 1; Semgrep only 0; both 0; neither 0

FullShield default-scan counts for these apps stay in BENCHMARK.md. This file does not retune rules.
Commercial scanners were not executed.
