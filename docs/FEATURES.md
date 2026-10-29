# FullShield features (3.1.2)

Inventory of what **3.1.2** adds. Planning source: [features2.md](features2.md) section B advanced extras B15–B18. This is a patch on 3.1.1. It adds no command, no CLI option, no rule id, no package export, and no new `FULLSHIELD_EXPERIMENTAL_*` flag.

Default `scan --json` findings stay byte-identical to 3.1.1 on single-package fixtures: same `(ruleId, file, line, severity)` multiset after sort. No stable rule id is removed. No stable finding field is removed. This version does not post pull-request comments, does not auto-merge, does not execute install scripts, and does not contact a host that is not already allowlisted. `clean-app` stays at 0 findings on the default scan.

The public description is [README.md](../README.md). The frozen command and output contract is [stability.md](stability.md).

## Experimental (`FULLSHIELD_EXPERIMENTAL_BUMP_PR`)

Same commands as 3.1.1: `bumps plan --from <scan.json>` and `bumps open --from <scan.json>`.

- Plan output is a JSON object. `bumps` is the ranked list. `skippedNotImported` counts `DEPS-VULN-001` rows whose reachability is `not-imported`. Those rows are still omitted from the pull requests.
- Rows that share a package name and the same target version become one pull request. `clears` is how many reachable findings that one upgrade covers. The pull-request body names that count only when it is greater than 1. The arguments still exclude merge and comment APIs.
- `installScripts` lists `preinstall`, `install`, and `postinstall` strings read from the installed `node_modules/<name>/package.json`. The strings are reported. They are never executed.
- When `FULLSHIELD_EXPERIMENTAL_PROVENANCE` is also `1`, a target version whose local registry cache says `dist.attestations` is absent is listed in `provenanceBlocked` and is not opened. A missing cache file does not block. The flag off leaves the 3.1.1 open list, plus the workspace grouping above.

With `FULLSHIELD_EXPERIMENTAL_BUMP_PR` unset, both subcommands still refuse before reading the file.
