# Demo

Captured from this checkout on 2026-10-16. Commands:

```bash
npm run build
NO_COLOR=1 node dist/cli/index.js scan test/fixtures/vulnerable-app
NO_COLOR=1 node dist/cli/index.js doctor . --offline
```

`scan` exited 1 because the fixture has findings at or above the default fail threshold. `doctor` exited 0.

## scan test/fixtures/vulnerable-app

```text
FullShield v0.1.3 — scanned 12 files in 222.38ms (modules: deps, secrets, sast, config)

CRITICAL (1)
  [DEPS-VULN-001] Vulnerable dependency lodash@4.17.11 (package.json:9)
    lodash@4.17.11
    lodash@4.17.11 is affected by GHSA-jf85-cpcp-j695 (Prototype Pollution in lodash).
    fix: Upgrade lodash to 4.17.12 or later (data from OSV).
    reachability: reachable
    docs: rules/DEPS-VULN-001.md

HIGH (21)
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

25 more — use --json

✖ 35 finding(s): 1 critical, 21 high, 8 medium, 3 low, 2 info
```

## doctor . --offline

```text
node: 24.21.0 ok
lockfile: package-lock.json
cache: /Users/k244p/.cache/fullshield/osv (1095 files)
flags: none
config: valid (failOn high, offline false)
osv: network skipped (--offline); reachability uses the local lockfile only
```
