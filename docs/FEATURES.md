# FullShield features (2.4.0)

Inventory of what **2.4.0** does. Everything 2.3.0 already ships stays. Planning source: [features2.md](features2.md) items **A8, A9, A10** only.

**Version note:** the request named `2.3.1`. Under R16a a patch cannot add features, commands, or flags. A8–A10 are features → this inventory is **2.4.0** (minor). Do not ship these as 2.3.1.

Default `scan --json` **findings** on single-package fixtures stay byte-identical to 2.3.0 on `vulnerable-app`, `clean-app`, and every current bench app (same `(ruleId, file, line, severity)` multiset after sort) when those trees are not multi-workspace. No stable rule id is removed. No stable finding field is removed. This version does not post pull-request comments, does not add a VS Code extension, does not ship Dashboard SaaS, does not scan containers/OS packages, and does not contact new hosts for EPSS/KEV.

`clean-app` stays at 0 high/critical findings. A `--repo` run uses local fixtures and does not park. Accuracy is never traded for speed. Invented timings are forbidden.

The public description is [README.md](../README.md). The frozen command and output contract is [stability.md](stability.md).

## This version (2.4.0)

### A8 — Monorepo workspace orchestration (stable)

- Promote Phase 54 workspace lockfile scanning from `FULLSHIELD_EXPERIMENTAL_WORKSPACES` into the **default** engine when the project is a multi-workspace tree (npm / pnpm / yarn workspaces with more than one package).
- Scan each workspace with its own lockfile when that file exists; attribute dependency findings to the workspace package that owns the locked version; merge findings deterministically (workspace name, then existing finding sort).
- A **single-package** repo (no workspace set, or one package only) stays finding-identical to 2.3.0 with the flag unset; the experimental flag may remain accepted as a no-op or force-on for tests.
- Show which workspace owns a reachable CVE in finding metadata and/or console grouping (no new rule id required if an existing field or `package` path already carries it; if a new stable field is required, name it in SPEC and update `docs/stability.md`).
- **R10:** if promoting workspaces changes default `scan --json` keys on any multi-workspace fixture that is part of the default-scan-diff set, the features file hereby approves that R10 for workspace trees only; single-package apps must stay EMPTY vs 2.3.0. Add a dedicated workspace fixture if none is in the diff set yet.
- `stableChange: true` only for workspace-attributed dep findings on multi-workspace trees; otherwise `false` for single-package.

### A9 — Policy-as-code pack (recommended profile)

- Ship a documented **policy pack** under `templates/policy/` (or equivalent) for orgs:
  - no reachable critical on `main` (fail when a reachable `critical` finding exists on that branch context),
  - secrets always fail (`failOn` / module rules so secret findings fail CI),
  - exceptions require `owner`, `reason`, and ISO `expires` (existing Phase 34 shape).
- Fold experimental policy (`FULLSHIELD_EXPERIMENTAL_POLICY` / `fullshield.policy.json`) into **`profile: "recommended"`** carefully: when `profile` is `recommended` (or `ci-strict` if SPEC names it), load and enforce the pack’s policy file if present; do **not** turn policy on for scans with no `profile` key (default scan without profile stays finding-key-identical to 2.3.0 aside from A8 workspace trees).
- Do not promote noisy experimental SAST rules into the default scan. Policy organizes fail/exit and exceptions; it does not add new SAST rule ids in this version.
- `fullshield init --recommended` (already in 2.3.0) also writes the starter policy pack when missing; document the pack in README.
- Doctor may warn when `profile` is set but `fullshield.policy.json` is missing, or when policy is invalid.

### A10 — Zero-config first PR (`init --ci`) — no PR comments

- Add `fullshield init --ci`: writes Action workflow + `fullshield.config.json` (and recommended policy pack from A9 when combined with `--recommended` or as documented defaults for `--ci`).
- When `gh` is available and the user is in a git repo with a remote, `--ci` may create a branch and open a pull request that **adds those files only** (documented; opt-out via `--no-pr` or dry-run). It does **not** require network hosts beyond GitHub as the user already uses for `gh`.
- After writing files (and optionally opening the PR), print the first scan result as **local** Markdown via the existing `--pr-summary` path (or equivalent deterministic summary to stdout / a file in the PR tree). It does **not** post a pull-request comment, does not request changes, does not open issues, and does not phone home (SPEC §31).
- README documents the flow and states clearly that FullShield never posts PR comments.

## Out of scope

- GitHub App / bot that posts PR comments or opens issues (SPEC §31) — including any “first scan comment” on the PR.
- VS Code / Cursor extension; Dashboard SaaS; EPSS/KEV; container/OS scanning.
- Auto-merge of any PR (including the `init --ci` PR).
- Promoting unrelated experimental SAST flags into default scan.
- Version **2.3.1** as the ship vehicle for this inventory (patch cannot hold these features).

## Acceptance (version-level)

- Single-package `default-scan-diff` vs `next` (2.3.0) is EMPTY.
- Multi-workspace fixture: findings attributed per workspace lockfile; documented R10 only if keys differ from 2.3.0 on that fixture.
- Policy pack templates exist; `profile: recommended` enforces them when the policy file is present; no profile → policy off (aside from explicit experimental flag).
- `init --ci` writes CI files; optional PR via `gh`; never posts a PR comment (unit/fixture tests assert absence of comment APIs).
- `npm run verify` green with empty HOME.
- `clean-app` stays at 0 high/critical findings.
