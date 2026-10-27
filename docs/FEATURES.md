# FullShield features (2.1.0)

Inventory of what 2.1.0 adds. Everything 2.0.2 already ships stays. Default `scan --json` does not change. No stable rule id is removed. No stable finding field is removed. Every new scanner is behind its own flag and stays off unless that flag is set to `1`. Each new flag also has a matching `scan --experimental-*` CLI option that sets the flag.

2.1.0 is a **minor**: five new experimental scanners with new rule ids and flags. It is not 2.0.3. A patch would only fix already-shipped behavior without a new rule id or flag. Production `npm audit --omit=dev` is already clean. The open vitest/vite/esbuild/tinypool advisories stay parked (phase 530); this version does not rewrite the lockfile for them. `clean-app` stays at 0 findings with every new flag off and on. A `--repo` run uses local fixtures and does not park. No check contacts a registry, opens a network connection, executes the scanned file, sends a Redis or search command, reads or writes object storage, starts a worker, or evaluates XPath.

The public description is [README.md](../README.md). The frozen command and output contract is [stability.md](stability.md).

## This version (2.1.0)

### Experimental (`FULLSHIELD_EXPERIMENTAL_REDIS`)

- **Redis command injection** — `scan --experimental-redis` sets the flag. Rule `SAST-REDIS-001` (CWE-94). Fires when the file imports `redis` or `ioredis` and `eval`, `evalSha`, `evalsha`, `call`, or `sendCommand` is invoked with an argument that is request data (`req.query`, `req.body`, `req.params`, `req.headers`, or a binding of those). A string-literal argument does not fire. `get`, `set`, `hget`, and `hset` of request data do not fire (they are not script or arbitrary-command sinks). Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to talk to Redis. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_XPATH`)

- **XPath injection** — `scan --experimental-xpath` sets the flag. Rule `SAST-XPATH-001` (CWE-643). Fires when the file imports `xpath`, `xpath.js`, or `libxmljs` and `select`, `select1`, or `evaluate` is invoked with an argument that is request data. A string-literal expression does not fire. A file that does not import one of those packages does not fire. Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to evaluate XPath. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_SEARCH`)

- **Search query injection** — `scan --experimental-search` sets the flag. Rule `SAST-SEARCH-001` (CWE-943). Fires when the file imports `@elastic/elasticsearch`, `@opensearch-project/opensearch`, or `elasticsearch` and `search` is invoked with a first-argument object whose `q` property, or nested `query.query_string.query` property, is request data. A string-literal query does not fire. `index`, `get`, and `ping` do not fire. Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to contact a search cluster. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_OBJECTKEY`)

- **Object-storage key from request data** — `scan --experimental-objectkey` sets the flag. Rule `SAST-OBJECTKEY-001` (CWE-22). Fires when the file imports `@aws-sdk/client-s3` or `aws-sdk` and `send` is called with a `GetObjectCommand`, `PutObjectCommand`, `DeleteObjectCommand`, or `ListObjectsV2Command` whose input `Key` or `Prefix` is request data, or when `s3.getObject` / `s3.putObject` / `s3.deleteObject` / `s3.listObjectsV2` is called with an options object whose `Key` or `Prefix` is request data. A string-literal key does not fire. `Bucket` alone being request data does not fire. Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to call object storage. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_WORKER`)

- **Worker entry from request data** — `scan --experimental-worker` sets the flag. Rule `SAST-WORKER-001` (CWE-94). Fires when `new Worker(...)` (from `worker_threads` or `node:worker_threads`) takes a first argument that is request data, or when the options object’s `workerData` property is request data. A string-literal module path with literal `workerData` does not fire. `Worker` constructed without that import style still matches the global `Worker` callee name only when the file also imports `worker_threads` or `node:worker_threads`. Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to start a worker. `clean-app` stays at 0 findings with the flag on.
