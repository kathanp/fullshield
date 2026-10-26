# FullShield features (2.0.1)

Inventory of what 2.0.1 adds. Everything 1.8.0 already ships stays. Default `scan --json` does not change. No stable rule id is removed. No stable finding field is removed. Experimental features stay off unless their flag is set to `1`.

2.0.1 adds five scanners. Each one follows request data through the existing taint model. A string literal does not fire. `clean-app` stays at 0 findings with every new flag off and on. A `--repo` run uses local fixtures and does not park. No check contacts a registry, opens a network connection, executes the scanned file, sends mail, writes a file, or launches a browser.

The public description is [README.md](../README.md). The frozen command and output contract is [stability.md](stability.md).

## This version (2.0.1)

### Experimental (`FULLSHIELD_EXPERIMENTAL_CRLF`)

- **Header injection** — `scan --experimental-crlf` sets the flag. With the flag on, `SAST-CRLF-001` fires when `setHeader`, `append`, `header`, or `set` is passed request data as the header value, or when `writeHead` is passed an options object whose header value is request data. Request data is `req.query`, `req.body`, `req.params`, `req.headers`, or a binding of those. A string-literal value does not fire. A numeric status alone does not fire. Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to send a response. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_MAIL`)

- **Mail header injection** — `scan --experimental-mail` sets the flag. With the flag on, `SAST-MAIL-001` fires when a file imports `nodemailer`, `@sendgrid/mail`, or `mailgun.js` and `sendMail` or `send` sets `to`, `cc`, `bcc`, `subject`, `from`, `replyTo`, `html`, or `text` from request data. A string-literal field does not fire. A `sendMail` in a file that does not import one of those three packages does not fire. Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to send mail. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_FORMULA`)

- **Spreadsheet formula injection** — `scan --experimental-formula` sets the flag. With the flag on, `SAST-FORMULA-001` fires when a file imports `csv-stringify`, `fast-csv`, `json2csv`, or `csv` and `stringify`, `write`, `writeToPath`, or `format` is passed request data, or when `writeFile` or `writeFileSync` writes request data to a path whose literal name ends in `.csv`. A string-literal row does not fire. A `writeFile` of request data to a path that does not end in `.csv` does not fire. Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to write a file. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_BROWSER`)

- **Browser-automation control** — `scan --experimental-browser` sets the flag. With the flag on, `SAST-BROWSER-001` fires when a file imports `puppeteer`, `puppeteer-core`, or `playwright` and `goto`, `setContent`, or `pdf` is passed request data. A string-literal URL or HTML body does not fire. A file that does not import one of those three packages does not fire. Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to launch a browser. `clean-app` stays at 0 findings with the flag on.

### Experimental (`FULLSHIELD_EXPERIMENTAL_DYNIMPORT`)

- **Dynamic import of request data** — `scan --experimental-dynimport` sets the flag. With the flag on, `SAST-DYNIMPORT-001` fires when `import()` is called with request data. A string-literal specifier does not fire. An `import()` of a binding that is not request data does not fire. Flag off: this module is not loaded and default `scan --json` does not include this rule. It refuses to load the module. `clean-app` stays at 0 findings with the flag on.
