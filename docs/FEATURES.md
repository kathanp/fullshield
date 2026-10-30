# FullShield features (3.4.2)

Inventory of what **3.4.2** adds. Planning source: features2.md section E advanced extras E29–E32. This is a patch on 3.4.1. It adds no command, no CLI option, no rule id file, no package export, and no new `FULLSHIELD_EXPERIMENTAL_*` flag.

Default `scan --json` findings stay byte-identical to 3.4.1 on single-package fixtures: same `(ruleId, file, line, severity)` multiset after sort. `clean-app` stays at 0 findings on the default scan. A `--repo` run does not park.

## Docs and a local check

- `docs/compatibility.md` lists the six existing CI jobs: ubuntu-24.04, macos-latest, and windows-latest, each with Node 22 and Node 24. npm, pnpm, yarn, bun, Express, Fastify, Nest, and Next are **not claimed**.
- `docs/vs-npm-audit.md` says the default scan classifies lockfile CVEs by reachability. It states no finding count.
- `templates/stranger-check.md` is the stranger-check steps. It is not a GitHub workflow. `.github/workflows` is unchanged.
- No company quote is published.

No new host. No new rule file.
