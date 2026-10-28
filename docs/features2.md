# FullShield market position and addable surface

Planning notes only. Not an approved version inventory. The shipping contract stays in [FEATURES.md](FEATURES.md), [stability.md](stability.md), and `SECURITY_SCANNER_SPEC.md`. Nothing here authorizes a build until it is copied into an approved `docs/FEATURES.md` for a named version.

## Honest take

“Top 1 npm security package” is not won by cloning Snyk + Sonar + `npm audit`. Those win on trust, integrations, and sales, not feature count. FullShield’s real wedge is already Node/TS backend + reachability + one CLI. Copying every enterprise checkbox dilutes that.

That market blurb is roughly right: early/niche, not mainstream. Using it today is fine for Node backends that want one local tool; it is not a Snyk replacement for large enterprises yet.

## What FullShield already has (and competitors often split)

| Area | You already ship |
| --- | --- |
| Deps + reachability | OSV + reachable / not-imported (headline) |
| SAST | Injection, XSS, SSRF, secrets, config |
| Supply chain | Malicious OSV, typosquat, lock hygiene |
| Runtime | Express/Fastify/Koa/Hono monitor + experimental RASP |
| Fix / CI | `fix`, `--fail-on`, SARIF, SBOM |
| Extras (mostly experimental) | Policy, VEX, MCP, LLM rules, DLP, host SSH |

## What others provide that you could add

List only — not committing to build. Each item has: **today**, **basic add**, **advanced add**, and **risk / SPEC note**. Prefer advanced items that strengthen the Node + reachability wedge, not generic enterprise checkboxes.

### A. Adoption blockers (biggest “why isn’t everyone using this?”)

1. **GitHub App / PR comments**
   - **Today:** `scan --pr-summary` prints Markdown; nothing posts to GitHub/GitLab.
   - **Basic:** GitHub App that comments on PRs with new findings vs baseline (deterministic, no AI).
   - **Advanced:** Check-run annotations per file/line; “Request changes” only on reachable high/critical; bot opens follow-up issues with `fix` patch attached; org-level allowlist of repos; signed webhook + least-privilege install.
   - **Risk:** SPEC historically rejects PR-comment bots as a product category; keep it opt-in, human-approved installs, never auto-merge.

2. **VS Code / Cursor extension**
   - **Today:** SPEC rejects a VS Code extension; MCP is the intended editor path.
   - **Basic:** Ship a first-class MCP pack + Cursor rules/skills that call `fullshield scan --json` and surface findings in chat.
   - **Advanced:** Language-server-style diagnostics via MCP resources; “apply this fix” that shells to `fullshield fix` with verification; workspace trust prompts; never silently scan `$HOME`.
   - **Risk:** Do not fork into a second product surface that diverges from CLI JSON.

3. [X] **One-click GitHub Action + marketplace** (2.3.0 — Action template + init; Marketplace listing still human)
   - **Today:** `init` can write workflows; marketplace listing/badges are thin.
   - **Basic:** Official Action with pinned digest, `fail-on`, SARIF upload to code scanning, status badge.
   - **Advanced:** Composite Action that runs scan → reachability-ranked summary → optional `fix` dry-run artifact; reusable workflow for monorepos; OIDC-only publish path documented as the trust story.
   - **Risk:** Unsigned marketplace Actions destroy trust; pin by SHA always.

4. **Dashboard SaaS (multi-repo history)**
   - **Today:** Local experimental dashboard only.
   - **Basic:** Hosted read-only history of scan JSON per repo/branch (trends, open vs closed findings).
   - **Advanced:** Org graph of reachable vulns across repos; “blast radius” when a shared lockfile package turns critical; SSO; retention policies; export to SIEM; still no claim of live attack prevention.
   - **Risk:** SaaS is a company product, not a CLI phase; needs privacy, billing, SOC2. Keep scanner useful offline without SaaS.

5. [X] **Signed / attested install for strangers** (2.3.0 — Verify-in-60s + provenance note; no Rekor/sigstore SaaS)
   - **Today:** Provenance on publish; stranger check exists in SPEC release steps.
   - **Basic:** README “verify in 60s” with `npx fullshield@x.y.z --version` + attested package link.
   - **Advanced:** SLSA build provenance on every release; public Rekor/sigstore page; install-guard that refuses non-attested tarballs in CI; weekly rebuild-reproducibility report.
   - **Risk:** Provenance theater without green gates (as with prior 2.1.0 publish timeouts) hurts more than it helps.

6. [X] **Speed as a product claim** (2.3.0 — README cites `bench/perf-v2.json` only; Next.js cold target still unmet)
   - **Today:** 2.2.0 shared AST / parallel modules / lazy taint; PERF2 pool + cache; stored Next.js cold scan still above target.
   - **Basic:** Publish reviewed p50 cold/warm numbers from `bench/perf-v2.json` only after a quiet-machine run.
   - **Advanced:** Public “scan under N seconds on app class X” SLA for CI; incremental `--changed` / diffscan as the default PR path; parse-cache hit-rate metrics in doctor; never invent numbers in docs.
   - **Risk:** Invented benches = credibility death. Accuracy never traded for speed (R26 / FEATURES rules).

7. [X] **Stable recommended defaults** (2.3.0 — `profile` + `init --recommended` + doctor warning)
   - **Today:** Hundreds of `FULLSHIELD_EXPERIMENTAL_*` flags; new users drown.
   - **Basic:** A documented `profile: recommended` (or `fullshield init --recommended`) that enables a small, reviewed set.
   - **Advanced:** Profiles per maturity (`ci-strict`, `pr-fast`, `prod-monitor`); doctor warns when experimental flags are on without a profile; promote flags only with R1 evidence.
   - **Risk:** Promoting noisy experimental rules into default scan is an R10 / CI-break event — needs human approval.

**A — more advanced (extra)**

- A8. [X] **Monorepo workspace orchestration** as a stable product (2.4.0 — multi-workspace lockfile scan by default; single-package unchanged).
- A9. [X] **Policy-as-code pack** for orgs (2.4.0 — `templates/policy/` + load with `profile: recommended` / `ci-strict`).
- A10. [X] **Zero-config first PR**: `init --ci` (2.4.0 — writes Action + config; optional `gh` recipe / injected runner; **no** PR comments per SPEC §31).

---

### B. Parity with Snyk / npm audit / Dependabot

8. **Auto PRs for dependency bumps (Dependabot-style + reachability)**
   - **Today:** `fix` can propose bumps; no always-on bot.
   - **Basic:** Nightly job opens one PR per reachable high/critical bump, ranked by reachability then severity.
   - **Advanced:** Group transitive bumps by root cause; prefer minimal override vs major bump; attach SBOM diff + VEX draft; reopen only when OSV changes; never edit lockfile by hand — always via package manager in CI.
   - **Risk:** Auto-merge is SPEC-rejected. Human merges only.

9. **License policy**
   - **Today:** Limited / experimental license signals.
   - **Basic:** Deny/allow lists on direct deps (e.g. no GPL in production).
   - **Advanced:** Transitive license graph with “introduced by” path; dual-license resolution; SBOM license attestation; CI fail only on production reachability path.
   - **Risk:** License law is not a CVE — keep messaging as policy, not “vulnerability”.

10. **Private registry / org advisory feed**
    - **Today:** Public OSV / npm registry paths.
    - **Basic:** Config for private npm registry + offline OSV cache dir.
    - **Advanced:** Org-private advisory JSON ingested like experimental ingest; mirror cache for air-gapped CI; sign org advisories; never phone home without explicit online mode.
    - **Risk:** R15 / network host allowlists — new hosts need SPEC amendment.

11. **EPSS / KEV prioritization**
    - **Today:** Phase 56 blocked (EPSS/CISA hosts) under R15.
    - **Basic:** Only after SPEC allows pinned hosts: enrich findings with EPSS/KEV flags, default scan still works offline without them.
    - **Advanced:** Combine EPSS × reachability × route exposure into a single deterministic priority (you already have experimental priority tables) — publish the formula; no ML black box.
    - **Risk:** Do not ship until hosts are explicitly allowed; offline must stay clean.

12. **Container / base-image scan**
    - **Today:** SPEC explicitly rejects OS/container as FullShield scope.
    - **Basic / Advanced:** Do **not** build this. Document “pipe Trivy SARIF into `ingest`” instead.
    - **Risk:** Faking container scanning destroys the honesty wedge.

13. **“Ignore forever” UX ↔ GitHub Security Advisories**
    - **Today:** Baseline / suppressions / experimental policy exceptions with expiry.
    - **Basic:** Stable exception file with owner + expiry; CI fails expired exceptions.
    - **Advanced:** Bidirectional sync with GitHub code scanning alerts (dismiss ↔ FullShield exception); require reason codes; audit log of who ignored a reachable critical.
    - **Risk:** “Forever” without expiry is how orgs go blind — default max expiry.

14. **Diff vs last scan as first-class CI gate**
    - **Today:** Experimental diff / deps-diff.
    - **Basic:** Promote `scan --diff` (or baseline-only new findings) to recommended CI.
    - **Advanced:** Gate on “new reachable” only; moved findings not treated as new; SARIF upload of delta; fail PR if reachable set grows.
    - **Risk:** Promoting experimental → default is R10 if output keys change.

**B — more advanced (extra)**

- B15. **Reachability-aware Dependabot replacement**: replace Dependabot entirely for npm — FullShield owns the only bump bot that skips not-imported CVEs.
- B16. **Malware / install-script sandbox report** for candidate upgrades (static only; never execute install scripts) before merge.
- B17. **Lockfile provenance gate**: refuse merge if resolved tarball lacks npm provenance when org policy requires it.
- B18. **Workspace-aware upgrade plans**: one PR upgrades the shared root dep that clears N reachable findings across packages.

---

### C. Parity with Semgrep / Sonar / CodeQL

15. **Higher default SAST recall on real apps**
    - **Today:** Strong core sinks; reviewed recall for untouched apps is not published; honesty > hype.
    - **Basic:** Expand sinks/framework packs behind flags; promote only with clean-app + FP bench silence.
    - **Advanced:** Continuous holdout program (Juice Shop, NodeGoat, realworld set) with human-reviewed labels; publish precision/recall only when `reviewed: true`; never weaken ground truth to “win”.
    - **Risk:** Fake recall is an explicit non-goal.

16. **Language packs beyond Node**
    - **Today:** Node/TS backends only.
    - **Basic / Advanced:** Usually a **bad bet** for “#1 npm tool”. If ever: separate package (`fullshield-python`) so the Node CLI stays sharp.
    - **Risk:** Dilutes the wedge; support cost explodes.

17. **Custom rule DSL (stable)**
    - **Today:** Experimental Semgrep-style user rules.
    - **Basic:** Stabilize a small YAML subset (pattern + message + severity) with versioned schema.
    - **Advanced:** Pack registry for org rules (local files only — no downloading third-party registries per SPEC reject); rule tests as fixtures; SARIF taxonomy mapping.
    - **Risk:** Bundling Semgrep registry is SPEC-rejected.

18. **IDE quick-fix**
    - **Today:** `fix` CLI; experimental fix-verify.
    - **Basic:** MCP/Cursor command: apply safe patch for one finding.
    - **Advanced:** Multi-finding fix groups; verify by re-scan only (no running project tests — R15); rollback snapshot; show diff before write.
    - **Risk:** Auto-running tests is rejected; keep verify = re-scan.

19. **Data-flow UI (taint graphs)**
    - **Today:** Trace fields on findings; HTML report exists.
    - **Basic:** HTML report draws source → sink edges for taint findings.
    - **Advanced:** Interactive graph (local only), click node → file:line; export Graphviz/Mermaid for PRs; SARIF code flows filled consistently.
    - **Risk:** Pretty graphs with wrong edges are worse than no graph — gate on determinism tests.

20. **Quality / security grade badges**
    - **Today:** No A/B/C score as a product claim.
    - **Basic:** Avoid letter grades; prefer counts by severity × reachability.
    - **Advanced (if forced):** Deterministic score formula published in docs; badge is “reachable critical = 0” not “Grade A”; never market as certification.
    - **Risk:** Marketing scores invite gaming and distrust.

**C — more advanced (extra)**

- C21. **Framework-deep packs as products**: Next App Router, Nest DI, tRPC, Prisma — each with FP-negative fixtures and promotion criteria.
- C22. **Cross-file summary caching** as default with byte-identical findings (extend 2.2.0 speed work into accuracy-preserving summaries).
- C23. **Second-order / stored XSS and SSRF** behind flags until FP rate is proven.
- C24. **Authz/IDOR** stays experimental until confidence model is honest; never default-fail CI on low-confidence IDOR.

---

### D. Parity with runtime / WAF / RASP vendors

21. **Safe-by-default block mode**
    - **Today:** Prefer `monitor`; experimental RASP is fail-open; no prevention claim.
    - **Basic:** Documented shadow mode → monitor → optional block for a tiny allowlisted sink set.
    - **Advanced:** Per-route policy; dry-run counters in production for N days; block only on high-confidence sinks with escape hatch header for break-glass; chaos tests for fail-open.
    - **Risk:** Claiming “prevents attacks” is marketing reject. Stay monitor-first.

22. **Attack dashboards + alerting**
    - **Today:** Slack/webhook notify on scan; runtime logs locally.
    - **Basic:** Structured runtime events to webhook (JSON) with rate limits.
    - **Advanced:** Local or SaaS timeline of blocked/monitored events; correlate to last scan finding IDs; PagerDuty; still not a SIEM replacement.
    - **Risk:** Multi-tenant cloud is company infra, not scanner honesty.

23. **eBPF / network layer**
    - **Today / forever for FullShield:** Out of product honesty — don’t chase.
    - **Alternative:** Integrate by ingesting external alerts; never pretend FullShield is CrowdStrike.

**D — more advanced (extra)**

- D24. **Runtime ↔ scan closed loop**: runtime sees SQLi-like payload → emit fingerprint → next CI scan highlights matching sinks.
- D25. **Canary / confirm** as a scheduled localhost job (already experimental confirm) with clear `unconfirmed ≠ pass`.
- D26. **DLP on responses** promoted carefully with size caps and false-positive budgets — never call it a DLP product.
- D27. **Framework middleware packs** with one-line setup and explicit mode enum (`monitor` | `block-experimental`).

---

### E. Trust & distribution (what makes tools “#1” in practice)

24. **Case studies + public benchmarks**
    - **Today:** Internal benches; comparison docs exist carefully; no fake “#1” claims.
    - **Basic:** Side-by-side on NodeGoat / Juice Shop / a real OSS API vs `npm audit` + Semgrep (same commit SHAs).
    - **Advanced:** Quarterly public scorecard: reachable vulns found, FP samples reviewed, cold-scan time; methodology frozen before the run (eval-plan style).
    - **Risk:** Cherry-picked wins destroy trust. Pre-register metrics.

25. **SOC2 / company security page**
    - **Today:** SECURITY.md for the package; company assurance is separate.
    - **Basic:** Public security page: how FullShield handles customer scan data (ideally: none in cloud-free mode).
    - **Advanced:** SOC2 if SaaS exists; pen-test summary; vulnerability disclosure SLAs; employee access controls — for the *company*, not claimed as scanner features.
    - **Risk:** Don’t block open-source CLI progress on SOC2 theater.

26. **Weekly “CVEs that matter for Node” digest**
    - **Today:** No productized digest.
    - **Basic:** Blog/script: new OSV npm CVEs filtered by “would be reachable in a typical Express app”.
    - **Advanced:** Personalized digest from org SBOM + last FullShield reachability classes; email/RSS; unsubscribe; never require SaaS for core scan.
    - **Risk:** Becoming a media company dilutes engineering — automate from the engine.

27. **Template configs per stack**
    - **Today:** Generic `init`.
    - **Basic:** Templates: Express API, Nest, Next App Router, Fastify, Hono.
    - **Advanced:** Template includes CI workflow, recommended profile, runtime middleware snippet, and a “first week” ignore baseline for known framework noise — with expiry.
    - **Risk:** Templates that hide real vulns are worse than no template.

28. **Trainer / interactive tour**
    - **Today:** Demo docs; stranger check on release.
    - **Basic:** `fullshield init --tour` walks scan → fix dry-run → CI in 5 minutes.
    - **Advanced:** Local tutorial app with planted vulns; progress checklist; links each finding to `rules/<ID>.md`; graduate into real repo scan.
    - **Risk:** Keep tutorial fixtures out of the published pack if they look like real secrets (concatenation rule).

**E — more advanced (extra)**

- E29. **Ambassador / OSS design partners**: 10 Node companies with public quotes after 30 days of CI use.
- E30. **Reproducible stranger pack**: GitHub Action that runs the SPEC stranger check on every tag and posts a green/red status to the release.
- E31. **Compatibility matrix**: Node 22/24 × npm/pnpm/yarn/bun lockfiles × Express/Fastify/Nest/Next — published and CI-gated.
- E32. **“FullShield vs npm audit” one-pager** that only claims what default scan actually does (reachability), with links to identical fixture runs.

## What I would not add to chase “#1”

- Full container/OS scanning
- Claiming “prevents attacks” / WAF replacement
- Fake recall numbers
- Becoming a general multi-language Sonar clone

## Short strategy (if the goal is market share)

1. Own one sentence: “The only Node scanner that ranks lockfile CVEs by real reachability and ships fix + runtime in one install.”
2. Close A1–A7 before cloning Snyk’s long tail.
3. Ship B8 (auto bump PRs ranked by reachability) — that’s a Dependabot killer for Node teams.
4. Publish speed + accuracy from real runs only.

## Lanes (pick one before a FEATURES.md version plan)

Still list-only until approved into `docs/FEATURES.md`:

1. **Adoption** — Action + PR comments + init path
2. **Dependabot killer** — reachability-ranked auto-bump PRs
3. **Accuracy / speed** — become the scanner people trust on real Node apps
4. **All of the above** as a multi-version roadmap (rank, not build everything at once)
