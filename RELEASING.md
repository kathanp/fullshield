# Releasing FullShield

Published from GitHub Actions with [npm trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC). There is no `NPM_TOKEN` secret. CI runs `npm publish --provenance --access public`. Do not edit the staged manifest. Provenance only works from a **public** GitHub repository.

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
3. Confirm CI: Linux, macOS, and Windows on Node 22 and 24 (6 jobs) are green. Stop if Windows is red.
4. GitHub **Settings → Code security**: Secret scanning, Push protection, Dependabot alerts. **Settings → Branches**: require the CI checks on `main`.
5. On npmjs.com, open **fullshield → Settings → Trusted Publisher → GitHub Actions**:
   - Organization or user: `kathanp`
   - Repository: `fullshield`
   - Workflow filename: `publish.yml`
   - Environment: leave blank
   - Allow npm publish: required for `npm publish --provenance`
   - Save. Do not add `NPM_TOKEN`. Do not create a GitHub Environment for publish.
6. Confirm the GitHub repo is **public**, then publish 0.1.0 from CI:

```bash
git pull
git tag v0.1.0
git push origin v0.1.0
```

   Watch the Actions **Publish** job until it is green (OIDC probe, `npm run build`, then `npm publish --provenance --access public`). CI on `main` is the test gate; Publish does not re-run `verify`.
7. Deprecate placeholders and confirm `latest`:

```bash
npm deprecate fullshield@0.0.0-stage "placeholder, use >=0.1.0"
npm deprecate fullshield@0.0.1 "placeholder, use >=0.1.0"
npm view fullshield dist-tags
```

   `dist-tags` must show `latest: 0.1.0`. The npmjs.com package page should show a Provenance badge.
8. Stranger check:

```bash
npm view fullshield
npx fullshield@0.1.0 scan ~/fullshield-bench/NodeGoat --offline
```

If a published version is broken: bump (never reuse a number), tag, then deprecate the bad version. Do not unpublish.

## Why 0.1.3 has no provenance

`v0.1.2` ran `npm publish --provenance`. The registry answered 403 (this package only accepts a staged publish plus maintainer 2FA). That attempt still wrote a sigstore transparency-log entry. `v0.1.3` then staged with provenance, sigstore returned 409 "an equivalent entry already exists", and `scripts/npm-stage-publish.mjs` retried **without** provenance. The maintainer approved that stage. `npm view fullshield@0.1.3 dist.attestations` is empty.

That retry is gone. A provenance failure now fails the publish job. After a successful stage, `scripts/provenance-gate.mjs` polls `dist.attestations` for 10 minutes and fails if it stays empty. Approve the staged version on npmjs.com within that window. Do not edit the staged manifest to inject a README ([npm/cli#9405](https://github.com/npm/cli/issues/9405)).

**Staged approval and README:** Approving a staged package can leave the registry packument `readme` empty even when the tarball contains `package/README.md` (`npm view fullshield@<version> readme` is blank; npmjs.com may keep showing the previous version). This is an npm registry/website issue, not a missing file in the pack. See [npm/cli#9405](https://github.com/npm/cli/issues/9405). Keep 2FA approval on. Do not inject README text into the staged manifest (Cloudflare WAF blocked that). Do not change the publish command to work around it.

## Later releases

1. Bump `package.json` version and finalize `CHANGELOG.md`.
2. Commit on `main`.
3. Tag and push `vX.Y.Z`.
