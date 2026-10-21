# SAST-SESSION-002

**Session fixation on login.** Experimental (`FULLSHIELD_EXPERIMENTAL_SESSION2=1`). CWE-384. Severity medium.

A login route writes `req.session.user`, `userId`, `uid`, or `auth*` without `req.session.regenerate` earlier in the file. `req.login` / `req.logIn` counts as regenerate only when the locked passport version is 0.6.0 or newer. An older passport is a finding that names that version.

## Remediation

Call `req.session.regenerate` before storing the user on the session.

See `SECURITY_SCANNER_SPEC.md` Section 46 phase 100.
