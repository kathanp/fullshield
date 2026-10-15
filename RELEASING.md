# Releasing FullShield

Published from GitHub Actions with [npm trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC). There is no `NPM_TOKEN` secret. `npm publish --provenance --access public` stays in `.github/workflows/publish.yml`. Provenance only works from a **public** GitHub repository.

The npm package `fullshield` already exists (`0.0.0-stage` and `0.0.1` placeholders, maintainer `kathan2404`). Do not publish another placeholder.

`package.json` `"repository"` must be `git+https://github.com/kathanp/fullshield.git` or provenance fails.

## Remaining launch steps

1. Create **https://github.com/kathanp/fullshield** as a **public** repo named `fullshield` with **no README**. Not private — provenance fails from private repos.
2. Push `main`:

```bash
cd ~/fullshield
git remote add origin https://github.com/kathanp/fullshield.git
git push -u origin main
```

   If GitHub push protection flags the AWS documentation example key in older test commits, open the block link, choose “It’s used in tests,” and push again.
3. Confirm CI: Linux, macOS, and Windows on Node 20 and 22 (6 jobs) are green. Stop if Windows is red.
4. GitHub **Settings → Code security**: Secret scanning, Push protection, Dependabot alerts. **Settings → Branches**: require the CI checks on `main`.
5. On npmjs.com, open **fullshield → Settings → Trusted Publisher → GitHub Actions**:
   - Organization or user: `kathanp`
   - Repository: `fullshield`
   - Workflow filename: `publish.yml`
   - Environment: leave blank
   - Save. Do not add `NPM_TOKEN`. Do not create a GitHub Environment for publish.
6. Confirm the GitHub repo is **public**, then publish 0.1.0 from CI:

```bash
git pull
git tag v0.1.0
git push origin v0.1.0
```

   Watch the Actions **Publish** job until it is green (`npm ci && npm run verify` then `npm publish --provenance --access public`).
7. Deprecate placeholders and confirm `latest`:

```bash
npm deprecate fullshield@"<0.1.0" "placeholder, use >=0.1.0"
npm view fullshield dist-tags
```

   `dist-tags` must show `latest: 0.1.0`. The npmjs.com package page should show a Provenance badge.
8. Stranger check:

```bash
npm view fullshield
npx fullshield@0.1.0 scan ~/fullshield-bench/NodeGoat --offline
```

If a published version is broken: bump (never reuse a number), tag, then deprecate the bad version. Do not unpublish.

## Later releases

1. Bump `package.json` version and finalize `CHANGELOG.md`.
2. Commit on `main`.
3. Tag and push `vX.Y.Z`.
