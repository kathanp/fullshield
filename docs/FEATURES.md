# FullShield features (2.3.0)

Inventory of what **2.3.0** does. Everything 2.2.0 already ships stays. Default `scan --json` **findings** stay byte-identical to 2.2.0 on vulnerable-app, clean-app, and every bench app (same `(ruleId, file, line, severity)` multiset after sort). No new rule id. No stable rule id is removed. No stable finding field is removed. This version does not post pull-request comments, does not add a VS Code extension, does not ship Dashboard SaaS, does not scan containers/OS packages, and does not contact new hosts for EPSS/KEV.

2.3.0 is a **minor** (R16a): adoption and distribution surface only. It does not change default scan findings. `stableChange: false`. No R10. Accuracy is never traded for speed. Numbers in docs come only from a stored bench run; invented timings are forbidden.

`clean-app` stays at 0 high/critical findings. A `--repo` run uses local fixtures and does not park.

The public description is [README.md](../README.md). The frozen command and output contract is [stability.md](stability.md). Planning context: [features2.md](features2.md) items **3, 5, 6, 7** only (hard SPEC rejects for PR bots / VS Code extension / SaaS stay out).

## This version (2.3.0)

### 3 — Official GitHub Action (no PR comments)

- Ship `templates/action/` as the Action wrapper SPEC Phase 59 already named (`kathanp/fullshield-action` or in-repo composite usable via `uses:`).
- The Action runs `fullshield scan`, uploads SARIF to code scanning when permissions allow, caches the baseline directory when configured, and **pins** the `fullshield` npm version (and Action refs by commit SHA in docs examples).
- It does **not** post a pull-request comment, does not request changes, does not open issues, and does not phone home.
- `fullshield init` may write a workflow that calls this Action (or the existing inline `npx` workflow remains valid). Marketplace listing steps are documented; publishing the Action to the Marketplace is a human release step, not an autopilot `npm publish`.
- README gains a short “GitHub Action” section with a SHA-pinned example and a status-badge snippet that points at the workflow file the user owns.

### 5 — Attested install story for strangers

- README gains a “Verify in 60 seconds” path: empty cache / fresh temp, `npx fullshield@2.3.0 --version`, link to the npm package page and to GitHub release/tag `v2.3.0`, and a one-line note that Publish stages with provenance (OIDC) — no new network hosts.
- Document the existing stranger-check commands from SPEC Section 2 (scan / json / sarif / fail-on / fix / init / sbom) as the post-publish gate humans already run; do not invent a new cloud attestation product.
- If Publish provenance is red for this version, stop (S6); do not claim attestation in README for a version that did not get a green provenance gate.
- No install-guard that phones home. No Rekor/sigstore SaaS dependency in the CLI.

### 6 — Speed as a claim (stored numbers only)

- Run the existing Phase 42 / Phase 78 / PERF2 harness on a quiet machine class documented for `bench/perf-v2.json`, store the new timings with `measured: true` and a reviewed-or-unreviewed label (R7).
- Update README Known Limitations / Section 28 **only** from that stored file. If the Next.js cold target is still unmet, say so; do not invent a number.
- Optional doctor lines for parse-cache / PERF2 when those flags are on (hit/miss counts already available or additive metadata) — must not change finding keys.
- Incremental `--changed` / experimental diffscan stay as they are unless a separate phase promotes them; this version does not make diffscan the default PR path.

### 7 — Recommended profiles (no default-scan promotion)

- Add a config key `profile` with values `recommended` | `ci-strict` | `pr-fast` | `prod-monitor` (exact set named in SPEC after this file is approved). Each profile is a documented bundle of **existing** flags and CLI defaults (fail-on, modules, offline-safe recommendations) — it does **not** turn on experimental SAST rules that change default `scan --json` finding keys.
- `fullshield init --recommended` writes `fullshield.config.json` with `profile: "recommended"` and the matching workflow snippet.
- `fullshield doctor` warns when many `FULLSHIELD_EXPERIMENTAL_*` env vars are set without a profile, or when a profile name is unknown.
- Promoting any experimental rule into the default scan is **out of scope** for 2.3.0 (would be R10). Profiles only organize what already exists.

## Out of scope

- GitHub App / bot that posts PR comments or opens issues (SPEC §31).
- VS Code / Cursor extension package (SPEC §31); MCP remains the editor path.
- Dashboard SaaS, SSO, SIEM product.
- EPSS/KEV hosts (Phase 56 still blocked).
- Container / OS scanning.
- Auto-merge of fix or bump PRs.
- New SAST rule ids; changing `expected-findings.json` or bench ground truth.
- Claiming “prevents attacks” or a WAF replacement.
- Version **3.1.0** (no Stable break → this inventory is **2.3.0**).

## Acceptance (version-level)

- `default-scan-diff` vs `next` (2.2.0) is EMPTY.
- `npm run verify` green with empty HOME.
- Action template exists, is tested, and docs show SHA pin + “does not post PR comments”.
- README verify-in-60s path matches package version 2.3.0.
- Any new speed sentence in README cites `bench/perf-v2.json` (or states the target is still unmet).
- Profile + `init --recommended` + doctor warning covered by unit tests; unknown profile rejected; default scan without profile unchanged.
