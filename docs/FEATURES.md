# FullShield features (2.0.2)

Inventory of what 2.0.2 fixes. Everything 2.0.1 already ships stays. Default `scan --json` does not change. No new flag. No new rule id. No stable rule id is removed. No stable finding field is removed. The same experimental flags stay off unless they are set to `1`.

2.0.2 tightens three of the 2.0.1 scanners so a common method name is not treated as the sink. `clean-app` stays at 0 findings with every flag off and on. A `--repo` run uses local fixtures and does not park. No check contacts a registry, opens a network connection, executes the scanned file, sends mail, writes a file, or launches a browser.

The public description is [README.md](../README.md). The frozen command and output contract is [stability.md](stability.md).

## This version (2.0.2)

### Experimental (`FULLSHIELD_EXPERIMENTAL_CRLF`)

- **Header method precision** — the flag and `scan --experimental-crlf` stay as they are. `SAST-CRLF-001` still fires for `setHeader`, `append`, `header`, and `writeHead` when the header value is request data. `set` fires only when the receiver is `res`, `resp`, `response`, or `reply`. `cache.set`, `map.set`, and `session.set` do not fire. A string-literal value does not fire. A numeric status alone does not fire. Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to send a response. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_MAIL`)

- **Mail send precision** — the flag and `scan --experimental-mail` stay as they are. `SAST-MAIL-001` still fires for `sendMail` when the file imports `nodemailer`, `@sendgrid/mail`, or `mailgun.js` and `to`, `cc`, `bcc`, `subject`, `from`, `replyTo`, `html`, or `text` is request data. `send` fires only when that same import is present and the receiver is `mail`, `transporter`, `transport`, `sg`, or `mg`, or the receiver name contains `mail`. `res.send` does not fire. A string-literal field does not fire. A file that does not import one of those three packages does not fire. Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to send mail. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_FORMULA`)

- **CSV writer precision** — the flag and `scan --experimental-formula` stay as they are. `SAST-FORMULA-001` still fires for `stringify` and `writeToPath` when the file imports `csv-stringify`, `fast-csv`, `json2csv`, or `csv` and an argument is request data. `write` and `format` do not fire when the receiver is `res`, `resp`, `response`, or `reply`. `writeFile` and `writeFileSync` of request data to a path whose literal name ends in `.csv` stay as they are. A string-literal row does not fire. A `writeFile` of request data to a path that does not end in `.csv` does not fire. Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to write a file. `clean-app` stays at 0 findings with the flag on.
