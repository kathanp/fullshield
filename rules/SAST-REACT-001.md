# SAST-REACT-001

**Unsanitized HTML binding.** Experimental (`FULLSHIELD_EXPERIMENTAL_BROWSER=1`). CWE-79. Severity medium.

`dangerouslySetInnerHTML` with a non-literal `__html`, Vue `v-html`, or Svelte `{@html}`, when the file does not mention DOMPurify or sanitize-html. A literal `__html` is not a finding. A server-side sanitize call in the same file clears it.

## Remediation

Sanitize the HTML with DOMPurify or sanitize-html before binding it.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 101.
