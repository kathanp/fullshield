# Dogfood: FullShield on FullShield (0.1.0)

`scan --offline` on this repo after release-prep. 42 findings. None are a live credential or a production server hole.

## Production / product code (`src/`, CLI)

**Zero findings.**

## Justified

| Finding | Where | Why we keep it |
|---|---|---|
| Fixture SAST / config / secrets / `AI-INJECT-001` | `test/fixtures/**` | Seeded on purpose. `vulnerable-app` is the acceptance corpus. |
| `SECRET-*` in unit/e2e tests | `test/unit/**`, `test/e2e/**` | Concatenated fakes (`'AKIA' + '…'`). Default config already ignores `**/*.test.ts`. |
| `CONFIG-HELMET-001` | `scripts/bench.mjs` | Loopback Express harness for `inspect()` p95. Not a network server. Finding has no line (file-level), so inline ignore cannot attach. |
| `CONFIG-BODYLIMIT-001` | `scripts/bench.mjs` | Same harness. Suppressed with `fullshield-ignore` on the `express.json()` line. |
| `CONFIG-INSTALLSCRIPT-001` | `package-lock.json` → `esbuild` | Transitive of `tsup`. We do not run its install script as a product feature. |
| `DEPS-DEPRECATED-001` | `eslint@9.39.5`, `glob@10.5.0` | Dev-only lockfile notices. eslint 9.39 is what the toolchain installed; glob is a transitive. Not shipped in the npm tarball’s runtime. |
| `CONFIG-INSTALLSCRIPT-001` | `test/fixtures/vulnerable-app/package-lock.json` | Fixture lockfile. |

## Replaced this release (looked like keys, were not)

| File | What | Change |
|---|---|---|
| `SECURITY_SCANNER_SPEC.md` | PEM header + `AKIA`+16 `X` example | Reworded so the secrets module does not treat the spec as a key |
| `benchmarks/ai-live-raw.json` | Fake `postgres://…` in a rejected `fix --ai` diff | Redacted |
| `test/unit/ai/provider.test.ts` | AWS docs example as one literal | Now two string literals joined with `+` |
| `test/unit/modules/secrets/rules.test.ts` | PEM headers as one literal | Now concatenated |

No committed TLS private key exists in this repo (HEAD or history). NodeGoat’s demo `server.key` lives only under `~/fullshield-bench` (outside the repo).

## History secrets scan

`scripts/history-secrets.mjs` ran the secrets module on every blob in all **23** commits (786 raw hits, 33 unique file+rule pairs).

**Zero real secrets.** Every hit is a fixture, a unit-test fake, or a spec example. Snippets in the report are already masked (`AKIA****`, `sk_t****`).

**Push-protection note:** six historical commits (phase-16 → harden-4-5) still contain the AWS documentation example key as a single literal (`AKIA` + the well-known `IOSFODNN7EXAMPLE` suffix, written in one piece) in `test/unit/ai/provider.test.ts`. HEAD is concatenated. The first push of that history may still trip GitHub secret scanning on those old commits (allow the secret or wait for a human history rewrite — this release does not rebase).
