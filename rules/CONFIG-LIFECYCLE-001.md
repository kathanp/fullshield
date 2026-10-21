# CONFIG-LIFECYCLE-001

**Root lifecycle script downloads remote code.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_LIFECYCLE=1`). CWE-829. Severity high. Module `config`.

The root `package.json` `scripts` `preinstall`, `install`, `postinstall`, or `prepare` contains `curl`, `wget`, `Invoke-WebRequest`, or an `http` URL piped to a shell. `"postinstall": "node scripts/build.js"` with no URL is not this finding. This is the application manifest. Lockfile `hasInstallScript` is unchanged.

## Remediation

Remove the downloader from the lifecycle script and run a local file instead.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 136.
