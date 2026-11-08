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

   That sentence describes the 0.1.0 launch. The workflow on this tree does not re-run `verify`. See [Today (3.6.1)](#today-361).
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

That retry is gone. A provenance failure now fails the publish job. After a successful stage, `scripts/provenance-gate.mjs` polls `dist.attestations` for 3 hours and fails if it stays empty. Approve the staged version on npmjs.com within that window. The publish job allows 6 hours so the poll is not killed first. Do not edit the staged manifest to inject a README ([npm/cli#9405](https://github.com/npm/cli/issues/9405)).

**Staged approval and README:** Approving a staged package can leave the registry packument `readme` empty even when the tarball contains `package/README.md` (`npm view fullshield@<version> readme` is blank; npmjs.com may keep showing the previous version). This is an npm registry/website issue, not a missing file in the pack. See [npm/cli#9405](https://github.com/npm/cli/issues/9405). Keep 2FA approval on. Do not inject README text into the staged manifest (Cloudflare WAF blocked that). Do not change the publish command to work around it.

## Today (3.9.0)

`package.json` is `3.9.0`. That number is not tagged and not on npm. `v3.8.0` stays the published release until this tag is staged. Pushing `v3.9.0` is a separate step. The tag workflow stages the package. The maintainer clicks the staged version on npmjs.com. Do not run `npm publish` or `npm login`. A minor waits 14 days after `v3.8.0` (2026-11-07) unless the maintainer says "waive the 14-day wait".

## Today (3.8.0)

`v3.8.0` is tagged. The 14-day wait was waived by the maintainer on 2026-11-07.

## Today (3.7.0)

`v3.7.0` is tagged and published. The 14-day wait was waived by the maintainer on 2026-11-05.

## Today (3.6.1)

A pull request to `main` runs `npm run verify` six times: Ubuntu, macOS, and Windows, on Node 22 and Node 24 (`.github/workflows/ci.yml`). `fail-fast` is false, so one slow or failed job holds the merge. Merging creates a new commit, and those six jobs start again on `main`. Pushing `vX.Y.Z` runs `.github/workflows/publish.yml`. That workflow does not run `npm run verify`. It runs the semver check, the pack budget, the build, the SBOM, and the stage. The maintainer clicks the staged version on npmjs.com. Do not run `npm publish` or `npm login`.

## Next release: 3.6.1

`docs/ROADMAP.md` puts the unfinished trust baseline, this release path, and the old 4.0.0–4.7.0 work in one release named 3.6.1. `v3.6.0` is already tagged for the four group flags. A tag that includes the default CI gate change cannot reuse that tag. The release path below is part of 3.6.1. The rest of the release does add commands, flags, and default-scan findings.

1. Six verify jobs stay on the pull request and on `main`: Ubuntu, macOS, and Windows, on Node 22 and Node 24. `npm run verify` runs in each.
2. Those six jobs are the merge gate. They are not moved to a schedule. The Windows Node 22 timeout on 3.6.0 was a 15-second test limit in `test/unit/deps/phase557-bump-pr.test.ts`, not a failed release.
3. Fast-forward `main` to the commit those six jobs tested. A merge commit is a new SHA, and GitHub would test it again.
4. Push the tag only after that job is green. Do not push the branch and the tag in one step. The tag does not wait for checks that have not finished.
5. The tag workflow stages the package. It keeps the semver check, the pack budget, the build, the SBOM, and the provenance gate. It does not run `npm run verify` again.
6. `main` is the tree. Do not update a `next` branch for this release.
7. The maintainer clicks the staged version on npmjs.com. The workflow does not put the version live.

Workflow edits for this tag, and no others:

- `.github/workflows/ci.yml`: keep `os: [ubuntu-24.04, macos-latest, windows-latest]` and `node: [22, 24]` on `pull_request` to `main` and on `push` to `main`.
- `.github/workflows/publish.yml`: delete the `Verify` step that runs `npm run verify`. Leave the semver check, pack budget, build, SBOM, sign, stage, and provenance gate.
