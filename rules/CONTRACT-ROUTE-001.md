# CONTRACT-ROUTE-001

**Route has no OpenAPI path.** CWE-1059. Requires `FULLSHIELD_EXPERIMENTAL_CONTRACT=1` and `--modules contract`.

An Express, Fastify, Nest, or Next route has no matching OpenAPI path and method. Hono and Koa are not compared. The check does not fetch a URL and does not install a package.

## Remediation

Add that method and path to the local OpenAPI file, or remove the route.
