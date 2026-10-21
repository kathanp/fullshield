# SAST-DOMXSS-001

**DOM XSS sink.** Experimental (`FULLSHIELD_EXPERIMENTAL_BROWSER=1`). CWE-79. Severity high.

Browser source (`location.hash`, `location.search`, `location.href`, `document.URL`, `document.referrer`, `window.name`, `event.data`) is written to `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, a string `setTimeout` / `setInterval`, `src` / `href` without an `https:` check, or jQuery `$(source)` / `.html()`. Server taint rules do not run browser sources.

## Remediation

Assign text with `textContent`, or sanitize HTML before writing it.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 101.
