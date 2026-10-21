# DEPS-SUFFIX-001

**Direct dependency adds a common suffix to a popular package.** Experimental (`FULLSHIELD_EXPERIMENTAL_NPM_SUFFIX=1`). CWE-494. Severity low.

The name is a popular package plus `-js`, `-node`, `-npm`, or `-lib`, and it is not itself on the popular list. Confidence is low. The message asks you to confirm intent. The popular name, and any other suffix, are not findings.

## Remediation

Keep the dependency only if that name is the package you meant.

See `SECURITY_SCANNER_SPEC.md` Section 47 phase 214.
