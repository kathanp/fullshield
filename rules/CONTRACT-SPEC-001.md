# CONTRACT-SPEC-001

**OpenAPI path has no route.** CWE-1059. Requires `FULLSHIELD_EXPERIMENTAL_CONTRACT=1` and `--modules contract`.

An `openapi.yaml` or `openapi.json` path and method has no matching Express, Fastify, Nest, or Next route. Query parameters and response bodies are not compared. A project with no OpenAPI file is not this finding.

## Remediation

Register that method and path, or remove it from the OpenAPI file.
