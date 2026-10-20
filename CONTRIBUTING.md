# Contributing

The source of truth is `SECURITY_SCANNER_SPEC.md`. The current version is in `package.json`. The public contract is `docs/stability.md`. Experimental flags stay off unless set. The package enforces Node >= 22.13. Do not mark ground truth `"reviewed": true`.

## Rules

Every detection rule needs:

1. A **positive fixture** (the rule must fire)
2. A **negative fixture** (the rule must stay quiet)
3. Coverage from `scripts/mutation-smoke.mjs` — if the suite still passes when the rule is disabled, the tests are fake and verify fails

Do not weaken existing tests or `test/fixtures/vulnerable-app/expected-findings.json` to make a change pass. If a test is genuinely wrong, stop and say so.

## Workflow

```bash
npm ci
npm run verify
```

`verify` is the same gate as CI. There is no `.only` / `.skip` / stubbed “not implemented” code.

## AI

`--ai explain` and `fix --ai` are **experimental**. `--ai triage` and `--ai logic` are not a public CLI surface. Internal library tests set `FULLSHIELD_AI_INTERNAL=1`.

## Secrets in fixtures

Build fake credentials by concatenation at runtime (`'AKIA' + '…'`). Never commit a realistic-looking key as a single literal. See spec §13.
