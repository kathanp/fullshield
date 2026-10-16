# FullShield rules

Each Core rule has a positive fixture in `test/fixtures/vulnerable-app` and a
negative counterpart in `test/fixtures/clean-app`.

## Secrets

| ID | What |
|---|---|
| [SECRET-AWS-001](SECRET-AWS-001.md) | AWS access key id |
| [SECRET-STRIPE-001](SECRET-STRIPE-001.md) | Stripe secret key |
| [SECRET-GITHUB-001](SECRET-GITHUB-001.md) | GitHub token |
| [SECRET-SLACK-001](SECRET-SLACK-001.md) | Slack token |
| [SECRET-GOOGLE-001](SECRET-GOOGLE-001.md) | Google API key |
| [SECRET-AIKEY-001](SECRET-AIKEY-001.md) | OpenAI/Anthropic-style key |
| [SECRET-PRIVKEY-001](SECRET-PRIVKEY-001.md) | PEM private key |
| [SECRET-DBURL-001](SECRET-DBURL-001.md) | DB URL with inline password |
| [SECRET-JWT-001](SECRET-JWT-001.md) | Hardcoded JWT secret |
| [SECRET-SESSION-001](SECRET-SESSION-001.md) | Hardcoded express-session secret |
| [SECRET-ENTROPY-001](SECRET-ENTROPY-001.md) | High-entropy assignment (low confidence) |
| [SECRET-ENVFILE-001](SECRET-ENVFILE-001.md) | Committed `.env` file |
| [SECRET-BUNDLE-001](SECRET-BUNDLE-001.md) | Secret-shaped `NEXT_PUBLIC_`/`VITE_` value in a client bundle (experimental) |

## Dependencies

| ID | What |
|---|---|
| [DEPS-VULN-001](DEPS-VULN-001.md) | OSV-known vulnerable package |
| [DEPS-TYPOSQUAT-001](DEPS-TYPOSQUAT-001.md) | Direct dep 1 edit from a popular name |
| [DEPS-DEPRECATED-001](DEPS-DEPRECATED-001.md) | Lockfile `deprecated` field |
| [DEPS-NOLOCK-001](DEPS-NOLOCK-001.md) | package.json without a lockfile |
| [SUPPLY-WORM-001](SUPPLY-WORM-001.md) | Experimental: token read + publish/registry/GitHub/workflow write |
| [SUPPLY-WORKFLOW-001](SUPPLY-WORKFLOW-001.md) | Experimental: dep writes `.github/` / git hooks / CI config |

## SAST

| ID | What |
|---|---|
| [SAST-SQLI-001](SAST-SQLI-001.md) | Tainted SQL concatenation |
| [SAST-NOSQLI-001](SAST-NOSQLI-001.md) | Raw `req.body`/`query` as Mongo filter, or a request field as a filter value |
| [SAST-CMDI-001](SAST-CMDI-001.md) | Tainted shell `exec` |
| [SAST-PATH-001](SAST-PATH-001.md) | Tainted path without resolve+prefix |
| [SAST-EVAL-001](SAST-EVAL-001.md) | `eval` / `new Function` / `vm` / `*.eval` |
| [SAST-SSRF-001](SAST-SSRF-001.md) | Tainted URL to HTTP client |
| [SAST-REDIRECT-001](SAST-REDIRECT-001.md) | Tainted `res.redirect` |
| [SAST-JWT-001](SAST-JWT-001.md) | `jwt.decode` / `algorithms: none` |
| [SAST-CRYPTO-001](SAST-CRYPTO-001.md) | `Math.random` tokens / md5 passwords |
| [SAST-PROTO-001](SAST-PROTO-001.md) | Unguarded recursive merge |
| [SAST-XSS-001](SAST-XSS-001.md) | HTML `res.send` or `<%-` / `{{{` |
| [SAST-AUTH-001](SAST-AUTH-001.md) | Data route with no auth middleware |
| [SAST-REDOS-001](SAST-REDOS-001.md) | Nested/overlapping regex quantifiers on tainted input (experimental) |
| [SAST-DESER-001](SAST-DESER-001.md) | Unsafe deserialize (`node-serialize`, js-yaml, funcster, serialize-javascript) (experimental) |
| [SAST-XXE-001](SAST-XXE-001.md) | XML external entities on tainted input (experimental) |
| [SAST-UPLOAD-001](SAST-UPLOAD-001.md) | multer/busboy/formidable without size/type, or `originalname` path (experimental) |
| [SAST-COOKIE-001](SAST-COOKIE-001.md) | Cookies missing httpOnly/secure/sameSite; hardcoded session secret (experimental) |
| [SAST-CSRF-001](SAST-CSRF-001.md) | Cookie-auth state-changing route without CSRF and sameSite (experimental) |
| [SAST-MASSASSIGN-001](SAST-MASSASSIGN-001.md) | `Model.create/update(req.body)` / `Object.assign(user, req.body)` (experimental) |
| [SAST-TIMING-001](SAST-TIMING-001.md) | Secret/token/HMAC compared with `===` not `timingSafeEqual` (experimental) |
| [SAST-HASH-001](SAST-HASH-001.md) | bcrypt/argon2/pbkdf2 below OWASP minimums (experimental) |
| [SAST-GQL-001](SAST-GQL-001.md) | GraphQL introspection in production, no depth limit, tainted resolver args (experimental) |

## Config

| ID | What |
|---|---|
| [CONFIG-HELMET-001](CONFIG-HELMET-001.md) | `express()` without `helmet()` |
| [CONFIG-BODYLIMIT-001](CONFIG-BODYLIMIT-001.md) | `express.json()` without `limit` |
| [CONFIG-CORS-001](CONFIG-CORS-001.md) | `origin:'*'` + `credentials:true` |
| [CONFIG-RATELIMIT-001](CONFIG-RATELIMIT-001.md) | Auth route without a limiter |
| [CONFIG-ERRSTACK-001](CONFIG-ERRSTACK-001.md) | `err.stack` sent to the client |
| [CONFIG-DIRLIST-001](CONFIG-DIRLIST-001.md) | `serveIndex()` directory listing |
| [CONFIG-DOCKER-LATEST-001](CONFIG-DOCKER-LATEST-001.md) | `FROM *:latest` |
| [CONFIG-DOCKER-ROOT-001](CONFIG-DOCKER-ROOT-001.md) | Dockerfile with no `USER` |
| [CONFIG-DOCKER-ENV-001](CONFIG-DOCKER-ENV-001.md) | `ENV *_SECRET=` / `*_KEY=` |
| [CONFIG-INSTALLSCRIPT-001](CONFIG-INSTALLSCRIPT-001.md) | Lockfile `hasInstallScript` |
| [CONFIG-TRUSTPROXY-001](CONFIG-TRUSTPROXY-001.md) | `trust proxy: true` with IP rate limiting (experimental) |

## Runtime DLP (experimental)

Requires `FULLSHIELD_EXPERIMENTAL_DLP=1` and `shieldGuard({ dlp: { mode } })`. Not a scan module.

| ID | What |
|---|---|
| [DLP-SECRET-001](DLP-SECRET-001.md) | Secret pattern in a JSON/text response |
| [DLP-STACK-001](DLP-STACK-001.md) | Stack trace in a response |
| [DLP-INTERNAL-001](DLP-INTERNAL-001.md) | Internal IP or hostname in a response |
| [DLP-CARD-001](DLP-CARD-001.md) | Luhn-valid card number in a response |
| [DLP-PII-001](DLP-PII-001.md) | Many emails on a one-email route |

## MCP config (experimental, `FULLSHIELD_EXPERIMENTAL_MCPCFG=1`)

| ID | What |
|---|---|
| [MCP-001](MCP-001.md) | Inline secret in MCP client config |
| [MCP-002](MCP-002.md) | Unpinned `npx` / `@latest` MCP server |
| [MCP-003](MCP-003.md) | Shell/exec or unrestricted fs-write tool, no allowlist |
| [MCP-004](MCP-004.md) | Tool-description instruction injection / hidden / ZWC |
| [MCP-005](MCP-005.md) | Remote MCP over plaintext `http://` |
