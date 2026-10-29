# FullShield features (3.1.1)

Inventory of what **3.1.1** adds. Planning source: [features2.md](features2.md) section B items 8–14 (basic). The advanced extras in that file are **3.1.2**, not this version.

Default `scan --json` findings stay byte-identical to 3.0.0 on single-package fixtures (`vulnerable-app`, `clean-app`, and current bench apps): same `(ruleId, file, line, severity)` multiset after sort. No stable rule id is removed. No stable finding field is removed. This version does not post pull-request comments, does not auto-merge, does not add a container or OS scanner, and does not contact EPSS, CISA KEV, or any host that is not already allowlisted. A `--repo` run does not park. `clean-app` stays at 0 findings on the default scan.

The public description is [README.md](../README.md). The frozen command and output contract is [stability.md](stability.md).

## Experimental (`FULLSHIELD_EXPERIMENTAL_BUMP_PR`)

- `bumps plan` ranks reachable high and critical dependency bumps from a local `scan --json` file. Reachable comes before severity. It refuses not-imported, unknown, and below-high rows.
- `bumps open` opens one pull request per ranked bump through an injected `gh` runner. It refuses `--merge`, review comments, and issue comments. A human merges.
- Ships `templates/fullshield-bumps.yml`, a nightly workflow the user copies. It does not merge and does not comment on pull requests.
- With the flag off, both subcommands refuse to run. A `--repo` scan does not open a pull request.

## Experimental (`FULLSHIELD_EXPERIMENTAL_LICENSE_POLICY`)

- Deny and allow lists on direct dependencies, read from the installed `package.json` `license` string. A missing install or a missing license stays silent. The finding says this is a license policy, not a vulnerability.
- An allow entry suppresses the same string on the deny list. Empty lists add nothing.
- With the flag off, the lists are ignored and default findings stay unchanged. A `--repo` run does not park.

## Experimental (`FULLSHIELD_EXPERIMENTAL_PRIVATE_REG`)

- Accepts `deps.registry` (https, no userinfo) and reads org advisories only from the local OSV cache file `org-advisories.json`.
- Refuses to contact the private host. Offline mode and online mode both stay on the cache. Live EPSS and CISA hosts stay off the allowlist.
- With the flag off, the registry key and the cache file are ignored. A `--repo` run does not park.

## Experimental (`FULLSHIELD_EXPERIMENTAL_EPSS_LOCAL`)

- Enriches existing findings from a local JSON file (`deps.epssFile`) with `epss`, `kev`, and `epssPriority`. It does not download a feed and does not add a finding.
- A score outside 0..1 rejects the file. With the flag off, the file is not read. A `--repo` run does not park.

## Dev checks

- README states that FullShield does not scan container or OS packages. Trivy SARIF can be passed to the existing `ingest` command. No container scanner is added. A `--repo` run does not park.

## Experimental (`FULLSHIELD_EXPERIMENTAL_EXCEPTIONS`)

- `fullshield.exceptions.json` requires `owner`, `reason`, and an ISO `expires`. Expired rows fail CI and do not suppress. An expiry more than 365 days ahead is rejected. There is no forever exception.
- With the flag off, the file is ignored. A `--repo` run does not park.

## Stable

- `init --recommended` also writes `.github/workflows/fullshield-diff.yml`, which runs `scan --diff` with `FULLSHIELD_EXPERIMENTAL_DIFFSCAN=1`. Default `scan` without `--diff` is unchanged. The workflow does not post pull-request comments. A `--repo` run does not park.
