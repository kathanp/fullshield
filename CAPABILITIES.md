# FullShield — capabilities brief

For developers and for coding agents (Claude, Cursor, others). The source of truth is
[`SECURITY_SCANNER_SPEC.md`](SECURITY_SCANNER_SPEC.md). The public contract is
[`docs/stability.md`](docs/stability.md). This file does not copy numbers; it links
to the files that generate them.

**Package:** [`fullshield` on npm](https://www.npmjs.com/package/fullshield).
**Scope:** Node.js / TypeScript backends only. Node >= 22.13.
**Version:** see `package.json`. The 1.x stable contract is `docs/stability.md`.

## What it is

A local, rule-based scanner and CI gate for Node/TS APIs:
detect → report → suggest fixes → fail CI → optional runtime monitor.

The main idea is dependency reachability: a CVE in the lockfile is ranked by whether
the app imports and calls the package, reaches it through another imported package,
or does not import it at all.

It is not a penetration test, a certification, a WAF, or a replacement for Semgrep,
npm audit, OSV-Scanner, or a dedicated secrets scanner. Use it beside them
([docs/use-with-other-tools.md](docs/use-with-other-tools.md)).

## Stable (no flag)

| Capability | Command |
|---|---|
| Scan (deps + reachability, secrets, SAST, config) | `npx fullshield scan` (`--json`, `--sarif`, `--fail-on high`) |
| Library | `import { scan } from 'fullshield'` |
| Baseline, new-findings-only CI | `scan --update-baseline` |
| Pre-commit secrets | `scan --staged`, `fullshield init` |
| Suggested and safe patches | `fullshield fix`, `fix --apply` (clean git tree) |
| Notifications | `fullshield notify` |
| CycloneDX SBOM | `fullshield sbom --format cyclonedx` |
| New-advisory watch | `fullshield watch` |
| URL posture (GET/HEAD headers only, your own sites) | `fullshield edge <url>` |
| Environment check | `fullshield doctor` |
| Request monitor middleware | `fullshield/runtime/express`, `/fastify` (`monitor` mode recommended) |

Rule list: [`rules/README.md`](rules/README.md). Each rule has `rules/<ID>.md`.

## Experimental (off unless a `FULLSHIELD_EXPERIMENTAL_*` flag is set)

Not production features. Not covered by the stable contract. The full list with flags
is in the README and `api/fullshield.api.json`. Includes: RASP sink hooks, virtual
patches, honeytokens, install guard, localhost exploit confirm, MCP server, LLM-app
rules, extra SAST classes, framework sources, AI explain and fix, ingest of other
tools' reports, priority score, attack paths, capability profiles, provenance signals,
type-aware receivers, user Semgrep-style rules, SPDX SBOM, `fullshield dev`.

## Measured results

- Benchmarks: [`BENCHMARK.md`](BENCHMARK.md). All ground truth is **unreviewed**. Tuning
  apps are `seen`. No recall or precision figure is citable yet.
- Tool comparison: [`COMPARISON.md`](COMPARISON.md). **Not citable** (see its banner).
- Known limitations: README "Known limitations" and spec Section 28.

There is no honest single "number of attacks it detects". It checks a fixed set of rule
classes in your code and config, plus whatever OSV knows about your locked versions.

## What it does not find

IDOR and other authorization or business-logic bugs (routes without auth middleware are
flagged as suspicious only), OS or network-service exploits, container or OS packages,
anything outside JS/TS. Experimental class rules cover CSRF, XXE, and deserialization
patterns; they are not stable.

## Instructions for coding agents

- Use it for Node/TS repos the user owns: `scan --fail-on high`, SARIF, SBOM, and to
  rank lockfile CVEs by reachability.
- Never scan, `edge`, or `confirm` a host the user is not authorized to test.
- MCP (`fullshield mcp --stdio`, experimental): `propose_fix` returns a diff only. Do not
  apply it unless the human asked.
- Do not claim the app is secure, that every vulnerability was found, or that any
  experimental feature is production-ready.
- Do not quote finding counts from memory or from old docs. Run the scan, or read
  `BENCHMARK.md` and repeat its labels (`unreviewed`, `seen`).
- When changing this repo: follow spec Section 0. Tests first. Never edit existing tests,
  fixtures, `expected-findings.json`, or ground truth to make anything pass. Never invent
  OSV data. Never publish, tag, or push `main`.
