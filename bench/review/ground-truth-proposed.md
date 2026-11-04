# Proposed ground-truth edits

Not applied. `bench/*/ground-truth.json` was not edited. Each row needs approval.

Match rule used by the scorer: same class, same file, line within 3. These proposals are the lines and classes. They are not a new score by themselves.

| app | current | current class | proposed | proposed class | reason |
|---|---|---|---|---|---|
| NodeGoat | `app/routes/session.js:138` | other | `app/routes/session.js:144` | other | `PASS_RE = /^.{1,20}$/` is on line 144. Line 138 is only the function start. `USER_RE` is line 140. |
| NodeGoat | `app/routes/allocations.js:14` | other | `app/routes/allocations.js:18` | other | Line 14 is the commented fix. The live code takes `userId` from `req.params` on line 18. |
| NodeGoat | `package.json:18` | deps | `package.json:17` | deps | Line 18 is `mongodb`. `marked` `0.3.5` is line 17. |
| Juice Shop | `routes/trackOrder.ts:17` | xss | `routes/trackOrder.ts:24` | xss | Line 17 checks for an iframe string. `res.json(result)` is line 24. |
| DVNA | `routes/app.js:1` | other | `routes/app.js:42` | other | Line 1 imports the router. The admin API route with only `isAuthenticated` is line 42. Line 44 is the users page. |
| DVNA | `routes/app.js:1` | other | `routes/app.js:56` | other | Line 1 imports the router. The POST handlers with no CSRF check are lines 56 and 58. |
| goof | `package.json:46` | deps | `package.json:45` | deps | Line 46 is `stream-buffers`. `st` `0.2.4` is line 45. |
| goof | `app.js:12` | other | `app.js:86` | other | Line 12 only requires `http`. `http.createServer(app).listen` is line 86. |
| Juice Shop | `package.json:1` | deps | `package.json:112` and `package.json:146` | deps | Line 1 is `{`. `express-jwt` `0.1.3` is line 112. `sanitize-html` `1.4.2` is line 146. |
| NodeGoat | `app/routes/session.js:116` | config | `server.js:95` | config | Line 116 stores `req.session.userId`. The cookie block with `httpOnly` is commented out at `server.js:95`. |
| DVNA | `core/appHandler.js:197` | config | `core/appHandler.js:197` | eval | The line is `mathjs.eval(req.body.eqn)`. An `eval` row already points at this line. There is no `err.stack` in the file. |
| vulnerable-node | `Dockerfile:21` | config | `Dockerfile:21` | none | The line is `USER node`. This commit does not run the image as root, so `config` does not match. |
| vulnerable-node | `README.md:133` | secrets | `README.md:133` | secrets | Leave this row. The line is the entry's own sentence: `PIPELINE_TOKEN` was removed from `HEAD` and remains in history. |
