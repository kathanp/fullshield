# RASP sink inventory

Experimental. Off unless `FULLSHIELD_EXPERIMENTAL_RASP=1`. Default mode `monitor`. Hooks fail open.

## Hooked

| Sink | When | What is checked |
|---|---|---|
| `node:sqlite` `DatabaseSync.exec` / `prepare` | builtin wrap | SQL structure-change |
| `child_process.exec` / `execSync` | builtin wrap | POSIX shell structure-change |
| `child_process.spawn` / `spawnSync` / `execFile` / `execFileSync` | builtin wrap, **only if `shell: true`** | POSIX shell structure-change |
| `fs` / `node:fs` `readFile(Sync)`, `writeFile(Sync)`, `appendFile(Sync)`, `open(Sync)`, `createReadStream`, `createWriteStream`, `stat(Sync)`, `lstat(Sync)`, `access(Sync)`, `readdir(Sync)`, `unlink(Sync)`, `rm(Sync)` | builtin wrap | path escape / null byte |
| `fs/promises` `readFile`, `writeFile`, `appendFile`, `open`, `stat`, `lstat`, `access`, `readdir`, `unlink`, `rm` | builtin wrap | path escape / null byte |
| `http.request` / `http.get` / `https.request` / `https.get` | builtin wrap | SSRF host (normalized + resolved IP) |
| `globalThis.fetch` (undici) | builtin wrap | SSRF host; **re-checks `Location` on followed redirects** |
| `node:vm` `runInNewContext` / `runInThisContext` / `runInContext` / `compileFunction` | builtin wrap | treated as structure-change of the code string |
| `pg` `Client.prototype.query` / `Pool.prototype.query` | `Module._load` | SQL text |
| `mysql2` `Connection.prototype.query` / `execute` (and `mysql2/promise` via name match) | `Module._load` | SQL text |
| `better-sqlite3` `prototype.exec` / `prepare` | `Module._load` | SQL text |
| `mongodb` `Collection.prototype.find` / `findOne` / `aggregate` / `updateOne` / `updateMany` / `deleteOne` / `deleteMany` / `countDocuments` | `Module._load` | NoSQL `$` operators from user input in the filter or pipeline |
| `mongoose` `Query.prototype.find` / `findOne` / `updateOne` / `updateMany` / `deleteOne` / `deleteMany` / `countDocuments`, `Model.aggregate` | `Module._load` | NoSQL `$` operators from user input in the filter or pipeline |
| `mongoose` `Query.prototype.$where` / `Model.prototype.$where` | `Module._load` | `$where` JS string structure-change |
| `@prisma/client` `PrismaClient.$queryRawUnsafe` / `$executeRawUnsafe` / `$queryRaw` / `$executeRaw`, `Prisma.raw` | `Module._load` | SQL text |
| `sequelize` `Sequelize.prototype.query` / `literal` | `Module._load` | SQL text |
| `knex` `.raw` / `Client.prototype.raw` / `whereRaw` / `orderByRaw` / `query` | `Module._load` | SQL text |
| `typeorm` `DataSource`/`EntityManager`/`QueryRunner`/`Connection.query`, `SelectQueryBuilder.where` | `Module._load` | SQL text |
| `drizzle-orm` `sql.raw` | `Module._load` | SQL text |
| `axios` `request` / `get` / `post` / `put` / `patch` / `delete` / `head` / `options`, including clients from `axios.create()` | `Module._load` | SSRF URL |
| `undici.request`, `Dispatcher.prototype.request`, `Agent.prototype.request` | `Module._load` | SSRF host |
| `diagnostics_channel` `undici:request:create` | subscribe | Second SSRF signal. The method wrap stays in place. |
| `express()` | `Module._load` | installs `raspContext()` (ALS + proto keys); `response.redirect` is SSRF-checked |

Request context is `AsyncLocalStorage` (`enterRaspContext` / `raspContext` middleware). Sink checks read the current store; they are intended to survive `await`, callbacks, and `child_process` / `http` / `fetch` completions.

## Not covered

| Sink | Why |
|---|---|
| `eval` / `new Function` | Not wrapped (would break the host). Use `--disallow-code-generation-from-strings`. |
| Template render (`ejs` / `pug` / `nunjucks` / `<%-`) | Not hooked. |
| `child_process.spawn` / `execFile` **without** `shell: true` | Args are data, not a shell string. |
| `pg` query values (bind params) | Only SQL `text` is tokenized. |
| ESM-only `import pg` without `Module._load` | Relies on CJS `_load` + `module.register` no-op loader. |
