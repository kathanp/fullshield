# Demo

Captured from this checkout on 2026-10-20 at **v1.2.0**. The transcript below is that run, unedited except that the home directory is shown as `~`. Commands:

```bash
npm run build
NO_COLOR=1 node dist/cli/index.js scan test/fixtures/vulnerable-app | sed "s#$HOME#~#g"
NO_COLOR=1 node dist/cli/index.js doctor . --offline | sed "s#$HOME#~#g"
```

`scan` exited 1 because the fixture has findings at or above the default fail threshold. `doctor` exited 0.

## scan test/fixtures/vulnerable-app

```text
FullShield v1.2.0 — scanned 12 files in 141.77ms (modules: deps, secrets, sast, config)
2 bumps (lodash 4.17.11 → 4.17.12, minimist 1.2.0 → 1.2.3) resolve 2 findings.
2 packages are never imported; removing them clears 1 advisory.

CRITICAL (1)
  [DEPS-VULN-001] lodash — 1 advisories, critical, reachable
    versions: 4.17.11
    package.json:9
    docs: rules/DEPS-VULN-001.md

HIGH (19)
  [SECRET-ENVFILE-001] Committed .env file (.env:1)
    .env is tracked in the repository. .env files hold live credentials and must never be committed.
    fix: Rotate this credential immediately, then load it from an environment variable or a secret manager. Removing it from the code is NOT enough: it remains visible in git history.
    docs: rules/SECRET-ENVFILE-001.md
  [SECRET-DBURL-001] Database connection string with inline password (.env:2)
    fake****
    Database connection string with inline password (fake****).
    fix: Rotate this credential immediately, then load it from an environment variable or a secret manager. Removing it from the code is NOT enough: it remains visible in git history.
    docs: rules/SECRET-DBURL-001.md
  [CONFIG-DOCKER-ENV-001] Secret assigned in Dockerfile ENV (Dockerfile:3)
    API_SECRET is baked into the image via ENV.
    fix: Pass secrets at runtime (or a secret store); never ENV them into the image.
    docs: rules/CONFIG-DOCKER-ENV-001.md
  [SAST-SQLI-001] SQL injection via string concatenation (src/data/alloc-dao.js:5)
    db.query('SELECT * FROM alloc WHERE value > ' + threshold)
    Tainted input crosses 3 files and reaches query.
    fix: Pass the value through a parameterized API or a recognized sanitizer before the sink.
    trace: src/routes/alloc.js:6 → src/services/alloc.js:5 → src/data/alloc-dao.js:5
    docs: rules/SAST-SQLI-001.md
  [CONFIG-CORS-001] Permissive CORS with credentials (src/index.js:16)
    cors({ origin: '*', credentials: true }) reflects any Origin with credentials.
    fix: Set origin to an explicit allow-list; never combine * with credentials: true.
    docs: rules/CONFIG-CORS-001.md
  [SAST-SQLI-001] SQL injection via string concatenation (src/index.js:20)
    db.query('SELECT * FROM users WHERE id = ' + req.query.id, (err, rows) => { res.json(rows); })
    Tainted input is concatenated into a SQL string passed to query/execute.
    fix: SQL injection via string concatenation. See https://cwe.mitre.org/data/definitions/89.html
    docs: rules/SAST-SQLI-001.md
  [SAST-PATH-001] Path traversal via unsanitized file path (src/index.js:27)
    res.sendFile(req.query.name)
    Tainted input is used as a file path without path.resolve + prefix check.
    fix: Path traversal via unsanitized file path. See https://cwe.mitre.org/data/definitions/22.html
    docs: rules/SAST-PATH-001.md
  [SAST-CMDI-001] Command injection via shell execution (src/index.js:32)
    exec(`ping ${req.body.host}`, (err, out) => { res.send(out); })
    Tainted input reaches a shell command (exec/execSync/spawn with shell: true).
    fix: Command injection via shell execution. See https://cwe.mitre.org/data/definitions/78.html
    docs: rules/SAST-CMDI-001.md
  [SAST-EVAL-001] Dynamic code execution with a non-literal (src/index.js:39)
    eval(req.query.expr)
    eval / vm.runInNewContext is called with a non-literal argument.
    fix: Dynamic code execution with a non-literal. See https://cwe.mitre.org/data/definitions/95.html
    docs: rules/SAST-EVAL-001.md
  [SAST-EVAL-001] Dynamic code execution with a non-literal (src/index.js:45)
    mathjs.eval(req.body.eqn)
    eval / vm.runInNewContext is called with a non-literal argument.
    fix: Dynamic code execution with a non-literal. See https://cwe.mitre.org/data/definitions/95.html
    docs: rules/SAST-EVAL-001.md
  [SECRET-AWS-001] Hardcoded AWS access key ID (src/index.js:53)
    AKIA****
    Hardcoded AWS access key ID (AKIA****).
    fix: Rotate this credential immediately, then load it from an environment variable or a secret manager. Removing it from the code is NOT enough: it remains visible in git history.
    docs: rules/SECRET-AWS-001.md
  [SECRET-STRIPE-001] Hardcoded Stripe secret key (src/index.js:56)
    sk_t****
    Hardcoded Stripe secret key (sk_t****).
    fix: Rotate this credential immediately, then load it from an environment variable or a secret manager. Removing it from the code is NOT enough: it remains visible in git history.
    docs: rules/SECRET-STRIPE-001.md
  [SAST-JWT-001] Insecure JWT verification (src/index.js:64)
    jwt.decode(req.headers.authorization)
    jwt.decode is used; it does not verify the signature (verify is missing).
    fix: Insecure JWT verification. See https://cwe.mitre.org/data/definitions/347.html
    docs: rules/SAST-JWT-001.md
  [SAST-NOSQLI-001] NoSQL injection via raw request object filter (src/index.js:70)
    db.find(req.body)
    req.body/req.query is passed directly into a Mongo-style filter.
    fix: NoSQL injection via raw request object filter. See https://cwe.mitre.org/data/definitions/943.html
    docs: rules/SAST-NOSQLI-001.md
  [SAST-SSRF-001] SSRF via tainted URL (src/index.js:75)
    fetch(req.query.url)
    Tainted URL is passed to fetch/axios/http.request.
    fix: SSRF via tainted URL. See https://cwe.mitre.org/data/definitions/918.html
    docs: rules/SAST-SSRF-001.md
  [SAST-SSRF-001] SSRF via tainted URL (src/index.js:82)
    needle.get(url)
    Tainted URL is passed to fetch/axios/http.request.
    fix: SSRF via tainted URL. See https://cwe.mitre.org/data/definitions/918.html
    docs: rules/SAST-SSRF-001.md
  [SAST-REDIRECT-001] Open redirect (src/index.js:87)
    res.redirect(req.query.next)
    Tainted input is passed to res.redirect.
    fix: Open redirect. See https://cwe.mitre.org/data/definitions/601.html
    docs: rules/SAST-REDIRECT-001.md
  [SAST-PROTO-001] Prototype pollution via recursive merge (src/index.js:93)
    merge(a[k] || {}, b[k])
    Recursive merge/assign of a tainted object without a __proto__ guard.
    fix: Prototype pollution via recursive merge. See https://cwe.mitre.org/data/definitions/1321.html
    docs: rules/SAST-PROTO-001.md
  [SAST-PROTO-001] Prototype pollution via recursive merge (src/index.js:99)
    merge({}, req.body)
    Recursive merge/assign of a tainted object without a __proto__ guard.
    fix: Prototype pollution via recursive merge. See https://cwe.mitre.org/data/definitions/1321.html
    docs: rules/SAST-PROTO-001.md

5 more actionable — use --json

13 more (not directly reachable, or below high confidence) — --all or see JSON

✖ 38 finding(s): 1 critical, 21 high, 11 medium, 3 low, 2 info
```

## doctor . --offline

```text
node: 24.22.0 ok
lockfile: package-lock.json
cache: ~/.cache/fullshield/osv (1800 files)
flags: none
config: valid (failOn high, offline false)
osv: network skipped (--offline); reachability uses the local lockfile only
```

`config: valid (failOn high, offline false)` is the value in `fullshield.config.json`, not the effective mode. The following line is the mode this command used: `osv: network skipped (--offline)`.
