# Live AI smoke (harden-4)

Not CI. Not a precision claim. Local Ollama only: `qwen2.5-coder:7b` at `http://127.0.0.1:11434`. Command: `npm run test:live-ai` (never invoked by `npm run verify`).

Smoke cap: `FULLSHIELD_AI_MAX_FINDINGS=8` (highest-severity first). NodeGoat live scan used modules `sast,config,secrets` (skipped 320 OSV hits). Raw job JSON: [`ai-live-raw.json`](ai-live-raw.json) (the failed NodeGoat `fix --ai` diff had a private key; that material was redacted before commit).

Ran 2026-10-14. Wall clock **507s**. Exit 0. The live path parsed model JSON (it no longer ignores the model and applies recorded fixtures).

## Time per job

| Job | Time | Outcome |
|---|---|---|
| vulnerable-app `--ai triage` | 122.8s | 8/34 findings labeled |
| vulnerable-app `--ai explain` | 108.7s | 8/34 findings explained |
| vulnerable-app `--ai logic` | 30.4s | +2 `source:ai` findings |
| vulnerable-app `fix --ai` | 6.2s | **no accepted patch** (2 attempts) |
| NodeGoat `--ai triage` | 107.3s | 8/14 findings labeled |
| NodeGoat `--ai explain` | 86.0s | 8/14 findings explained |
| NodeGoat `--ai logic` | 23.2s | **0** logic findings |
| NodeGoat `fix --ai` | 13.1s | **no accepted patch** (2 attempts) |

Roughly 10–16s per triage/explain call after the model was warm.

## Triage vs known true / false positives

### vulnerable-app

The fixture is seeded with real rule hits (`expected-findings.json`). There is no known false positive in the top-8 budget. The model labeled 4 `true-positive`, 2 `likely-false-positive`, 2 `needs-review`.

| Finding | Known | Model | Honest call |
|---|---|---|---|
| `DEPS-VULN-001` critical on lockfile | TP (lodash CVE) | LFP | **wrong** — confused it with the `expresss` typosquat |
| `SECRET-ENVFILE-001` on `.env` | TP for the rule | LFP | **wrong** — treated the fixture disclaimer as “not a secret” |
| `SECRET-DBURL-001` on `.env` | TP | needs-review | incomplete; reasoning was closer than the verdict |
| `CONFIG-DOCKER-ENV-001` | TP | TP | verdict ok; reasoning described the wrong Docker issue (root user) |
| `SAST-SQLI-001` `alloc-dao.js` | TP (cross-file) | needs-review | incomplete; reasoning itself described SQLi |
| `CONFIG-CORS-001` | TP | TP | verdict ok; reasoning listed unrelated vulns |
| `SAST-SQLI-001` `src/index.js` | TP | TP | ok |
| `SAST-PATH-001` | TP | TP | verdict ok; reasoning claimed the rule detects every vuln class |

**Accuracy on this budget:** 4/8 verdicts match “this is a real finding.” 2/8 are wrong LFPs on true positives. 2/8 punt. This is not precision 1.00.

### NodeGoat (`sast` + `config` + `secrets`, 14 findings, 8 labeled)

Known TPs in the labeled set: committed TLS key, `$where` NoSQLi, `eval` ×3, open redirect, SSRF (`needle`), error-stack leak.

| Finding | Known | Model | Honest call |
|---|---|---|---|
| `SECRET-PRIVKEY-001` `artifacts/cert/server.key` | TP | LFP | **wrong** |
| `SAST-NOSQLI-001` `$where` | TP | LFP | **wrong** (claimed quotes “escape” it) |
| `SAST-EVAL-001` ×3 `contributions.js` | TP | LFP ×3 | **wrong** |
| `SAST-REDIRECT-001` | TP | needs-review | incomplete; reasoning described the open redirect |
| `SAST-SSRF-001` `research.js` | TP | needs-review | incomplete; reasoning described SSRF |
| `CONFIG-ERRSTACK-001` | TP | LFP | **wrong** |

**0/8 labeled `true-positive`.** 6 known TPs dismissed as LFP. The live model is not a reliable triage layer on NodeGoat.

Known NodeGoat FPs (`SECRET-DBURL-001` on README placeholders, `CONFIG-HELMET-001` on `tutorial.js`) were **not in the 8-finding budget** (lower severity), so this smoke does not measure them.

## Explain

Explanations were junior-readable and often better than the triage verdicts (NodeGoat privkey / eval / NoSQLi write-ups named the real issue). They also hallucinated: lockfile “explain” spent a paragraph on the `expresss` typo; CORS explain said the whole file is an intentional demo. Useful as a draft, not as an authority.

## Logic hunter (real vs wrong)

**vulnerable-app (+2):**

- `AI-IDOR-001` on `GET /user` — the route is concatenated SQL on `req.query.id` (`SAST-SQLI-001`). There is no auth/ownership layer to fail. **Wrong class** (SQLi, not IDOR).
- `AI-MASSASSIGN-001` on `POST /settings` `merge({}, req.body)` — recursive merge of attacker JSON. Closer to prototype pollution (already `SAST-PROTO-001`) than mass assignment onto a user document. **Overclaim / wrong class.**

**NodeGoat (0 findings):** missed the known A4 IDOR (tutorial / allocations by user id). Empty `findings` array. **Miss.**

## `fix --ai` verify loop

Neither target produced an accepted patch.

- vulnerable-app: 2 attempts, targeted `.env`, wrote a nonsense replacement (`SECRET-DBURL-001` as file contents). Verify rejected it. User tree untouched.
- NodeGoat: 2 attempts, targeted `artifacts/cert/server.key` and proposed deleting the PEM. Verify rejected it (finding would not cleanly disappear without new issues / tests). User tree untouched.

The verify loop did its job. The model did not.

## Live-path bugs fixed while wiring this smoke

The Phase 14–16 code called the provider and then applied `fixtureTriage` / `fixtureExplain` / `fixtureLogic` / `fixtureFix` anyway. Live mode now parses the model JSON (`src/ai/parse.ts`). Ollama uses `POST /api/chat` + `format: json` and reads `message.content`. `FULLSHIELD_AI_LIVE=1` is the only live switch (so unit tests stay fixture-safe). Live `fix --ai` does **not** fall back to a recorded fixture patch. Recorded fixtures were not edited.

## Takeaway

The AI layer is now a working local-model path, and it is **not** good enough to advertise. Mark `--ai` experimental. Do not quote fixture “precision 1.00” as model quality.

---

## Phase 24 re-run (2026-10-14)

Same command: `npm run test:live-ai`. Same model `qwen2.5-coder:7b` at `http://127.0.0.1:11434`. Wall clock **768s**. Exit 0. Raw job JSON: [`ai-live-raw.json`](ai-live-raw.json) (NodeGoat `fix --ai` PEM diff redacted again before commit).

### Time per job

| Job | Time | Outcome |
|---|---|---|
| vulnerable-app `--ai triage` | 190.3s | 8/34 labeled: 3 TP / 3 LFP / 2 needs-review |
| vulnerable-app `--ai explain` | 101.5s | 8/34 explained |
| vulnerable-app `--ai logic` | 41.0s | +2 `source:ai` (`AI-IDOR-001`, `AI-MASSASSIGN-001`) |
| vulnerable-app `fix --ai` | 4.9s | **no accepted patch** (2 attempts, targeted `.env`) |
| NodeGoat `--ai triage` | 190.8s | 8/14 labeled: 1 TP / 3 LFP / 4 needs-review |
| NodeGoat `--ai explain` | 179.4s | 8/14 explained |
| NodeGoat `--ai logic` | 33.1s | **0** logic findings |
| NodeGoat `fix --ai` | 24.0s | **no accepted patch** (2 attempts; proposed deleting `server.key`) |

### Honest call vs harden-4

vulnerable-app triage still misses true positives (`SECRET-ENVFILE-001` LFP, `CONFIG-DOCKER-ENV-001` LFP, cross-file `SAST-SQLI-001` LFP because it claimed parameterized queries). 3/8 TP is **worse than** the harden-4 4/8 on this budget.

NodeGoat triage improved slightly: `SAST-NOSQLI-001` is now TP (was LFP). The three `eval` hits are still LFP (model believed a comment “fixed” them). Privkey / redirect / SSRF / err.stack are needs-review. **1/8 TP.** Still not a reliable triage layer.

Logic hunter: same two wrong-class hits on vulnerable-app; NodeGoat still **misses** the known A4 IDOR.

`fix --ai`: verify loop still rejects both targets. Trees untouched.

**Unchanged takeaway:** live Ollama is a working path and is **not** good enough to advertise. `--ai` stays experimental.
