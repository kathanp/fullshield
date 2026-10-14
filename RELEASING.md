# Releasing FullShield

Published from GitHub Actions with [npm trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC). There is no `NPM_TOKEN` secret.

## One-time npm setup

1. Create the npm package (first publish) or open the existing `fullshield` package.
2. **Trusted Publisher** → GitHub Actions:
   - Organization or user: the GitHub owner of this repo
   - Repository: `fullshield`
   - Workflow filename: `publish.yml`
   - Environment name: `npm` (must match `.github/workflows/publish.yml`)
3. In GitHub: **Settings → Environments → New environment** named `npm`. Optional: require a reviewer before the publish job runs.

Do not add `NPM_TOKEN` to repository secrets.

## Cut a release

1. Version is already `0.1.0` in `package.json` (or bump it).
2. Finalize `CHANGELOG.md` under that version heading.
3. Commit on `main` (`release-prep` or a follow-up).
4. Tag and push:

```bash
git tag v0.1.0
git push origin main
git push origin v0.1.0
```

The `v*` tag starts `.github/workflows/publish.yml`, which runs `npm ci && npm run verify` then `npm publish --provenance --access public`. Provenance is attached by npm from the OIDC token (`id-token: write`). The repo must be **public** for provenance attestations to be useful.

## After publish

- Confirm https://www.npmjs.com/package/fullshield
- Confirm the publish run shows provenance (no `NODE_AUTH_TOKEN` / `NPM_TOKEN` in the log)
