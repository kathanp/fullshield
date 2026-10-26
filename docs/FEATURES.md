# FullShield features (1.8.0)

Inventory of what 1.8.0 changes. Everything 1.7.0 already ships stays, including tagged-template SQL, the `execFile` command path, `FULLSHIELD_EXPERIMENTAL_DEEP`, and the 1.6.0 experimental flags. Default use is still a Node.js/TypeScript scan that detects, classifies, reports, notifies, suggests fixes, and can gate CI. Experimental features stay off unless their flag is set to `1`.

1.8.0 fixes a scan crash and the open dependency advisories in this repository. It does not add a rule id, a flag, or a default-scan finding. Default `scan --json` on a project whose lockfile parses is unchanged. `clean-app` stays at 0 findings. A `--repo` run uses local fixtures and does not park.

The public description is [README.md](../README.md). The frozen command and output contract is [stability.md](stability.md).

## This version (1.8.0)

No check contacts a registry, opens a network connection, executes the scanned file, or spawns a process. The published package's hard dependencies are unchanged: a production `npm audit` of this repository reports no advisory.

### Stable (default scan, no flag)

- **A lockfile that cannot be parsed does not abort the scan** — `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, and the same files inside a workspace directory, are read as they are today when the text parses. When the text does not parse, that file is skipped, the dependency module returns no findings for it, and secrets, SAST, and config still run. The scan command exits with the result of the modules that did run, instead of throwing. A lockfile that parses keeps the same findings it has today. It refuses to repair the lockfile and refuses to contact a registry. `clean-app` stays at 0 findings.

### Dev checks

These are not scan rules. They are not packed into the published tarball. They do not change default `scan --json`.

- **Test-toolchain advisories** — `vitest`, `@vitest/coverage-v8`, `@vitest/mocker`, `vite`, `vite-node`, `esbuild`, and `tinypool` move to versions `npm audit` reports as clean. They stay devDependencies. Existing tests stay as they are. If those versions cannot keep `npm run verify` green without editing a test, this item is left out of the release.

- **body-parser in the dev install** — the dev installs of `express` and `@modelcontextprotocol/sdk` resolve `body-parser` outside the ranges `npm audit` currently reports (`<1.20.9` and `>=2.0.0 <2.4.0`). The optional peer ranges stay. The scanner does not open a server. If a patched release cannot be installed without a new hard dependency, this item is left out of the release.
