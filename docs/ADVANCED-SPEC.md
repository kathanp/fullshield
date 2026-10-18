# Advanced spec

Branch `feat/advanced`. Default `scan` stays the same unless a flag below is set. Nothing here is a recall claim.

## In this branch

- CI reports (`FULLSHIELD_EXPERIMENTAL_CI_REPORTS=1`): `--github-annotations`, `--junit`, `--gitlab`.
- Scan diff (`FULLSHIELD_EXPERIMENTAL_DIFF=1`): compares two `scan --json` files. The match key ignores the line number. It uses rule, file, severity, and the snippet or message. Two findings that share that text stay distinct. A line shift is a move, not a new finding. A changed message with the same finding id is a move.
- GitLab Code Quality `fingerprint` uses that same line-independent value.
- SARIF is `scan --sarif`. It was already implemented. Every report format (console, JSON, SARIF, Markdown, HTML, GitHub annotations, JUnit, GitLab) now masks AWS, GitHub, Stripe, and Slack token shapes to the first 4 characters plus `****` before writing them.
- Baseline file `.fullshield-baseline.json` may include `suppressions`. Each row needs `ruleId`, `owner`, `reason`, and an ISO `expires`. Optional `file`. A future row hides that finding. A missing field or a past date does not hide it, and the scan exits 1. Rewriting the baseline keeps the suppression rows.
- GitHub Actions, still behind `FULLSHIELD_EXPERIMENTAL_IAC=1`: unpinned actions, `pull_request_target`, broad permissions, secret logging, plus `IAC-GHA-INJECT-001` (`${{ github.event.* }}` inside `run:`) and `IAC-GHA-PRCHECKOUT-001` (that trigger also checks out pull-request code).
- Lockfile checks in `checkLockfileIntegrity`: non-https or non-`registry.npmjs.org` resolved URLs (`SUPPLY-LOCKURL-001`), and a resolved entry with no integrity (`SUPPLY-LOCKINTEGRITY-001`). Called by the supply helpers, not by default `scan`.
- Dependency confusion (`SUPPLY-CONFUSION-001`) already exists behind `FULLSHIELD_EXPERIMENTAL_VEX=1`. `checkProvenance(previouslyHad, currentlyHas)` returns `SUPPLY-PROVENANCE-001` only when the caller passes `true, false`. It does not compare two published versions by itself. A local cache file can say whether one exact `name@version` had provenance. A missing file stays unknown.
- Git history secrets already exist behind `FULLSHIELD_EXPERIMENTAL_SECRETS_ADV=1` and `scan --history`. The walk now stops after 500 commits (`FULLSHIELD_HISTORY_MAX`, clamped to 1–5000). When that cap drops older commits, console and JSON say `scanned N of M commits`. The secret text in those findings is masked.
- Copyleft notice (`FULLSHIELD_EXPERIMENTAL_LICENSE=1`): `DEPS-LICENSE-001` when an installed direct dependency's `package.json` says GPL or AGPL. No `node_modules` means no finding. LGPL is not flagged. The license is read, not guessed.

## Already in the product, not rebuilt

- Config file is `fullshield.config.json` (modules, `failOn`, path `ignore`, baseline path, SAST size). Severity overrides and exceptions with owner, reason, and expiry are `fullshield.policy.json` (`FULLSHIELD_EXPERIMENTAL_POLICY=1`). A second `.fullshield.yml` is not added.
- `scan --staged` scans the git index for pre-commit.
- Incremental scan is `scan --changed` / `--since` behind `FULLSHIELD_EXPERIMENTAL_PLATFORM=1`.
- `listWorkspaces` reads npm and pnpm workspace globs behind that same flag. It does not scan each workspace with its own lockfile.
- Offline OSV cache is `scan --offline` / `--offline-safe`.
- Framework header, CORS, and cookie checks already exist as config and experimental class rules.

## Not in this branch

- Custom SAST or secret rules in YAML or JS.
- A pull-request comment bot.
- A VS Code extension.
- Per-workspace lockfile scans.
