# DEPS-PUBLISHCONFIG-002

**Private package sets publishConfig.access to public.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_PUBLISHCONFIG=1`). CWE-668. Severity medium.

`private` is `true` and `publishConfig.access` is `public`. A private package with no publishConfig is not this finding.

## Remediation

Remove publishConfig.access or set it to restricted.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 145.
