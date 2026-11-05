# Ground-truth check

Suggestions only. `reviewed` stays false in every ground-truth file. Those files were not edited.
Opinion is whether the code on that line matches the class.
Juice Shop rows whose file is `data/static/challenges.yml` are the challenge catalog, not the vulnerable statement.

## nodegoat app/routes/contributions.js:32

- class: `eval`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a1.html
- opinion: **YES**. The code on this line matches the class and the description.

```
31|        // Insecure use of eval() to parse inputs
32|        const preTax = eval(req.body.preTax);
33|        const afterTax = eval(req.body.afterTax);
```

## nodegoat app/data/allocations-dao.js:78

- class: `nosqli`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a1.html
- opinion: **YES**. The code on this line matches the class and the description.

```
77|                return {
78|                    $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
79|                };
```

## nodegoat app/routes/session.js:64

- class: `other`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a1.html
- opinion: **YES**. The code on this line matches the class and the description.

```
63|                if (err.noSuchUser) {
64|                    console.log("Error: attempt to login with invalid user: ", userName);
65|
```

## nodegoat app/data/user-dao.js:25

- class: `crypto`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a2.html
- opinion: **YES**. The code on this line matches the class and the description.

```
24|            benefitStartDate: this.getRandomFutureDate(),
25|            password //received from request param
26|            /*
```

## nodegoat app/routes/session.js:116

- class: `config`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a2.html
- opinion: **NO**. The line stores a user id on the session. It does not set cookie flags.

```
115|            // `req.session.regenerate(() => {})`
116|            req.session.userId = user._id;
117|            return res.redirect(user.isAdmin ? "/benefits" : "/dashboard");
```

## nodegoat app/routes/session.js:138

- class: `other`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a2.html
- opinion: **NO**. The line is the start of validateSignup. The weak password regex is not on this line.

```
137|
138|    const validateSignup = (userName, firstName, lastName, password, verify, email, errors) => {
139|
```

## nodegoat app/views/layout.html:75

- class: `xss`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a3.html
- opinion: **YES**. The code on this line matches the class and the description.

```
74|                    <li class="dropdown user-dropdown">
75|                        <a href="#" class="dropdown-toggle" data-toggle="dropdown"><i class="fa fa-user"></i> {{firstName}} {{lastName}} <b class="caret"></b></a>
76|                        <ul class="dropdown-menu">
```

## nodegoat app/routes/allocations.js:14

- class: `other`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a4.html
- opinion: **NO**. This line is inside a comment and reads userId from the session, which is the fix described above it.

```
13|        // Fix for A4 Insecure DOR -  take user id from session instead of from URL param
14|        const { userId } = req.session;
15|        */
```

## nodegoat server.js:10

- class: `config`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a5.html
- opinion: **YES**. The code on this line matches the class and the description.

```
9|const swig = require("swig");
10|// const helmet = require("helmet");
11|const MongoClient = require("mongodb").MongoClient; // Driver for connecting to MongoDB
```

## nodegoat app/data/profile-dao.js:42

- class: `other`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a6.html
- opinion: **unsure**. The function accepts ssn and bank fields, but this line does not show them being stored.

```
41|
42|    this.updateUser = (userId, firstName, lastName, ssn, dob, address, bankAcc, bankRouting, callback) => {
43|
```

## nodegoat app/routes/benefits.js:31

- class: `other`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a7.html
- opinion: **unsure**. The line reads userId and a date from the body. A missing admin check is not visible here.

```
30|        const {
31|            userId,
32|            benefitStartDate
```

## nodegoat server.js:7

- class: `other`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a8.html
- opinion: **YES**. The code on this line matches the class and the description.

```
6|const session = require("express-session");
7|// const csrf = require('csurf');
8|const consolidate = require("consolidate"); // Templating library adapter for Express
```

## nodegoat package.json:18

- class: `deps`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a9.html
- opinion: **NO**. Line 18 is mongodb. marked@0.3.5 is the previous line.

```
17|    "marked": "0.3.5",
18|    "mongodb": "^2.1.18",
19|    "needle": "2.2.4",
```

## nodegoat app/routes/index.js:72

- class: `redirect`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/a10.html
- opinion: **YES**. The code on this line matches the class and the description.

```
71|        // Insecure way to handle redirects by taking redirect url from query string
72|        return res.redirect(req.query.url);
73|    });
```

## nodegoat app/routes/profile.js:59

- class: `other`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/redos.html
- opinion: **YES**. The code on this line matches the class and the description.

```
58|        // const regexPattern = /([0-9]+)\#/;
59|        const regexPattern = /([0-9]+)+\#/;
60|        // Allow only numbers with a suffix of the letter #, for example: 'XXXXXX#'
```

## nodegoat app/routes/research.js:16

- class: `ssrf`
- source: https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/tutorial/ssrf.html
- opinion: **YES**. The code on this line matches the class and the description.

```
15|            const url = req.query.url + req.query.symbol;
16|            return needle.get(url, (error, newResponse, body) => {
17|                if (!error && newResponse.statusCode === 200) {
```

## juice-shop routes/login.ts:34

- class: `sqli`
- source: https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html
- opinion: **YES**. The code on this line matches the class and the description.

```
33|    verifyPreLoginChallenges(req) // vuln-code-snippet hide-line
34|    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true }) // vuln-code-snippet vuln-line loginAdminChallenge loginBenderChallenge loginJimChallenge
35|      .then((authenticatedUser) => { // vuln-code-snippet neutral-line loginAdminChallenge loginBenderChallenge loginJimChallenge
```

## juice-shop routes/search.ts:23

- class: `sqli`
- source: https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html
- opinion: **YES**. The code on this line matches the class and the description.

```
22|    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
23|    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
24|      .then(([products]: any) => {
```

## juice-shop routes/trackOrder.ts:18

- class: `nosqli`
- source: https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html
- opinion: **YES**. The code on this line matches the class and the description.

```
17|    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return id.includes('<iframe src="javascript:alert(`xss`)">') })
18|    db.ordersCollection.find({ $where: `this.orderId === '${id}'` }).then((order: any) => {
19|      const result = utils.queryResultToJson(order)
```

## juice-shop routes/showProductReviews.ts:36

- class: `nosqli`
- source: https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html
- opinion: **YES**. The code on this line matches the class and the description.

```
35|
36|    db.reviewsCollection.find({ $where: 'this.product == ' + id }).then((reviews: Review[]) => {
37|      const t1 = new Date().getTime()
```

## juice-shop routes/updateProductReviews.ts:18

- class: `nosqli`
- source: https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html
- opinion: **YES**. The code on this line matches the class and the description.

```
17|    db.reviewsCollection.update( // vuln-code-snippet neutral-line forgedReviewChallenge
18|      { _id: req.body.id }, // vuln-code-snippet vuln-line noSqlReviewsChallenge forgedReviewChallenge
19|      { $set: { message: req.body.message } },
```

## juice-shop routes/userProfile.ts:65

- class: `eval`
- source: https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html
- opinion: **YES**. The code on this line matches the class and the description.

```
64|          }
65|          username = eval(code) // eslint-disable-line no-eval
66|        } catch (err) {
```

## juice-shop routes/redirect.ts:18

- class: `redirect`
- source: https://pwning.owasp-juice.shop/companion-guide/latest/part2/unvalidated-redirects.html
- opinion: **YES**. The code on this line matches the class and the description.

```
17|      challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
18|      res.redirect(toUrl)
19|    } else {
```

## juice-shop lib/insecurity.ts:136

- class: `redirect`
- source: https://pwning.owasp-juice.shop/companion-guide/latest/part2/unvalidated-redirects.html
- opinion: **YES**. The code on this line matches the class and the description.

```
135|  for (const allowedUrl of redirectAllowlist) {
136|    allowed = allowed || url.includes(allowedUrl) // vuln-code-snippet vuln-line redirectChallenge
137|  }
```

## juice-shop routes/trackOrder.ts:17

- class: `xss`
- source: https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html
- opinion: **NO**. The line checks whether the id contains an iframe payload. It does not render HTML.

```
16|
17|    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return id.includes('<iframe src="javascript:alert(`xss`)">') })
18|    db.ordersCollection.find({ $where: `this.orderId === '${id}'` }).then((order: any) => {
```

## juice-shop server.ts:290

- class: `config`
- source: https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-misconfiguration.html
- opinion: **YES**. The code on this line matches the class and the description.

```
289|  /* /ftp directory browsing and file download */ // vuln-code-snippet neutral-line directoryListingChallenge
290|  app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true })) // vuln-code-snippet vuln-line directoryListingChallenge
291|  app.use('/ftp(?!/quarantine)/:file', servePublicFiles()) // vuln-code-snippet vuln-line directoryListingChallenge
```

## juice-shop server.ts:302

- class: `config`
- source: https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-misconfiguration.html
- opinion: **YES**. The code on this line matches the class and the description.

```
301|  /* /logs directory browsing */ // vuln-code-snippet neutral-line accessLogDisclosureChallenge
302|  app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', { icons: true, view: 'details' })) // vuln-code-snippet vuln-line accessLogDisclosureChallenge
303|  app.use('/support/logs', verify.accessControlChallenges()) // vuln-code-snippet hide-line
```

## juice-shop package.json:1

- class: `deps`
- source: https://pwning.owasp-juice.shop/companion-guide/latest/part2/vulnerable-components.html
- opinion: **NO**. Line 1 is the opening brace of package.json, not a vulnerable package.

```
1|{
2|  "name": "juice-shop",
```

## juice-shop data/static/challenges.yml:3

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
2|-
3|  name: 'Password Hash Leak'
4|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:14

- class: `xss`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
13|-
14|  name: 'API-only XSS'
15|  category: 'XSS'
```

## juice-shop data/static/challenges.yml:42

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
41|-
42|  name: 'Admin Registration'
43|  category: 'Improper Input Validation'
```

## juice-shop data/static/challenges.yml:53

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
52|-
53|  name: 'Admin Section'
54|  category: 'Broken Access Control'
```

## juice-shop data/static/challenges.yml:70

- class: `deps`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
69|-
70|  name: 'Arbitrary File Write'
71|  category: 'Vulnerable Components'
```

## juice-shop data/static/challenges.yml:88

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
87|-
88|  name: 'Bjoern''s Favorite Pet'
89|  category: 'Broken Authentication'
```

## juice-shop data/static/challenges.yml:101

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
100|-
101|  name: 'Blockchain Hype'
102|  category: 'Security through Obscurity'
```

## juice-shop data/static/challenges.yml:117

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
116|-
117|  name: 'NFT Takeover'
118|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:130

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
129|-
130|  name: 'Mint the Honey Pot'
131|  category: 'Improper Input Validation'
```

## juice-shop data/static/challenges.yml:141

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
140|-
141|  name: 'Wallet Depletion'
142|  category: 'Miscellaneous'
```

## juice-shop data/static/challenges.yml:152

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
151|-
152|  name: 'Web3 Sandbox'
153|  category: 'Broken Access Control'
```

## juice-shop data/static/challenges.yml:163

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
162|-
163|  name: 'Blocked RCE DoS'
164|  category: 'Insecure Deserialization'
```

## juice-shop data/static/challenges.yml:181

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
180|-
181|  name: 'CAPTCHA Bypass'
182|  category: 'Broken Anti Automation'
```

## juice-shop data/static/challenges.yml:196

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
195|-
196|  name: 'Change Bender''s Password'
197|  category: 'Broken Authentication'
```

## juice-shop data/static/challenges.yml:207

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
206|-
207|  name: 'Christmas Special'
208|  category: 'Injection'
```

## juice-shop data/static/challenges.yml:220

- class: `xss`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
219|-
220|  name: 'CSP Bypass'
221|  category: 'XSS'
```

## juice-shop data/static/challenges.yml:237

- class: `xss`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
236|-
237|  name: 'Client-side XSS Protection'
238|  category: 'XSS'
```

## juice-shop data/static/challenges.yml:265

- class: `xss`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
264|-
265|  name: 'DOM XSS'
266|  category: 'XSS'
```

## juice-shop data/static/challenges.yml:280

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
279|-
280|  name: 'Database Schema'
281|  category: 'Injection'
```

## juice-shop data/static/challenges.yml:293

- class: `config`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
292|-
293|  name: 'Deprecated Interface'
294|  category: 'Security Misconfiguration'
```

## juice-shop data/static/challenges.yml:311

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
310|-
311|  name: 'Easter Egg'
312|  category: 'Broken Access Control'
```

## juice-shop data/static/challenges.yml:325

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
324|-
325|  name: 'Email Leak'
326|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:336

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
335|-
336|  name: 'Empty User Registration'
337|  category: 'Improper Input Validation'
```

## juice-shop data/static/challenges.yml:345

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
344|-
345|  name: 'Ephemeral Accountant'
346|  category: 'Injection'
```

## juice-shop data/static/challenges.yml:358

- class: `config`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
357|-
358|  name: 'Error Handling'
359|  category: 'Security Misconfiguration'
```

## juice-shop data/static/challenges.yml:372

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
371|-
372|  name: 'Expired Coupon'
373|  category: 'Improper Input Validation'
```

## juice-shop data/static/challenges.yml:383

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
382|-
383|  name: 'Extra Language'
384|  category: 'Broken Anti Automation'
```

## juice-shop data/static/challenges.yml:397

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
396|-
397|  name: 'Five-Star Feedback'
398|  category: 'Broken Access Control'
```

## juice-shop data/static/challenges.yml:422

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
421|-
422|  name: 'Forged Feedback'
423|  category: 'Broken Access Control'
```

## juice-shop data/static/challenges.yml:437

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
436|-
437|  name: 'Forged Review'
438|  category: 'Broken Access Control'
```

## juice-shop data/static/challenges.yml:449

- class: `deps`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
448|-
449|  name: 'Forged Signed JWT'
450|  category: 'Vulnerable Components'
```

## juice-shop data/static/challenges.yml:465

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
464|-
465|  name: 'Forgotten Developer Backup'
466|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:482

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
481|-
482|  name: 'Forgotten Sales Backup'
483|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:496

- class: `deps`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
495|-
496|  name: 'Frontend Typosquatting'
497|  category: 'Vulnerable Components'
```

## juice-shop data/static/challenges.yml:507

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
506|-
507|  name: 'GDPR Data Erasure'
508|  category: 'Broken Authentication'
```

## juice-shop data/static/challenges.yml:519

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
518|-
519|  name: 'GDPR Data Theft'
520|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:531

- class: `xss`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
530|-
531|  name: 'HTTP-Header XSS'
532|  category: 'XSS'
```

## juice-shop data/static/challenges.yml:547

- class: `crypto`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
546|-
547|  name: 'Imaginary Challenge'
548|  category: 'Cryptographic Issues'
```

## juice-shop data/static/challenges.yml:563

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
562|-
563|  name: 'Leaked Access Logs'
564|  category: 'Observability Failures'
```

## juice-shop data/static/challenges.yml:577

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
576|-
577|  name: 'Leaked Unsafe Product'
578|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:593

- class: `deps`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
592|-
593|  name: 'Legacy Typosquatting'
594|  category: 'Vulnerable Components'
```

## juice-shop data/static/challenges.yml:622

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
621|-
622|  name: 'Login Amy'
623|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:637

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
636|-
637|  name: 'Login Bender'
638|  category: 'Injection'
```

## juice-shop data/static/challenges.yml:653

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
652|-
653|  name: 'Login Bjoern'
654|  category: 'Broken Authentication'
```

## juice-shop data/static/challenges.yml:667

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
666|-
667|  name: 'Login Jim'
668|  category: 'Injection'
```

## juice-shop data/static/challenges.yml:682

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
681|-
682|  name: 'Login MC SafeSearch'
683|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:695

- class: `config`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
694|-
695|  name: 'Login Support Team'
696|  category: 'Security Misconfiguration'
```

## juice-shop data/static/challenges.yml:711

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
710|-
711|  name: 'Manipulate Basket'
712|  category: 'Broken Access Control'
```

## juice-shop data/static/challenges.yml:722

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
721|-
722|  name: 'Misplaced Signature File'
723|  category: 'Observability Failures'
```

## juice-shop data/static/challenges.yml:736

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
735|-
736|  name: 'Multiple Likes'
737|  category: 'Broken Anti Automation'
```

## juice-shop data/static/challenges.yml:748

- class: `crypto`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
747|-
748|  name: 'Nested Easter Egg'
749|  category: 'Cryptographic Issues'
```

## juice-shop data/static/challenges.yml:820

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
819|-
820|  name: 'Password Strength'
821|  category: 'Broken Authentication'
```

## juice-shop data/static/challenges.yml:837

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
836|-
837|  name: 'Payback Time'
838|  category: 'Improper Input Validation'
```

## juice-shop data/static/challenges.yml:847

- class: `crypto`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
846|-
847|  name: 'Premium Paywall'
848|  category: 'Cryptographic Issues'
```

## juice-shop data/static/challenges.yml:861

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
860|-
861|  name: 'Privacy Policy'
862|  category: 'Miscellaneous'
```

## juice-shop data/static/challenges.yml:879

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
878|-
879|  name: 'Privacy Policy Inspection'
880|  category: 'Security through Obscurity'
```

## juice-shop data/static/challenges.yml:894

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
893|-
894|  name: 'Product Tampering'
895|  category: 'Broken Access Control'
```

## juice-shop data/static/challenges.yml:923

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
922|-
923|  name: 'Repetitive Registration'
924|  category: 'Improper Input Validation'
```

## juice-shop data/static/challenges.yml:935

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
934|-
935|  name: 'Reset Bender''s Password'
936|  category: 'Broken Authentication'
```

## juice-shop data/static/challenges.yml:950

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
949|-
950|  name: 'Reset Bjoern''s Password'
951|  category: 'Broken Authentication'
```

## juice-shop data/static/challenges.yml:965

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
964|-
965|  name: 'Reset Jim''s Password'
966|  category: 'Broken Authentication'
```

## juice-shop data/static/challenges.yml:979

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
978|-
979|  name: 'Reset Morty''s Password'
980|  category: 'Broken Anti Automation'
```

## juice-shop data/static/challenges.yml:994

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
993|-
994|  name: 'Retrieve Blueprint'
995|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:1005

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1004|-
1005|  name: 'SSRF'
1006|  category: 'Broken Access Control'
```

## juice-shop data/static/challenges.yml:1038

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1037|-
1038|  name: 'Score Board'
1039|  category: 'Miscellaneous'
```

## juice-shop data/static/challenges.yml:1050

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1049|-
1050|  name: 'Security Policy'
1051|  category: 'Miscellaneous'
```

## juice-shop data/static/challenges.yml:1064

- class: `xss`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1063|-
1064|  name: 'Server-side XSS Protection'
1065|  category: 'XSS'
```

## juice-shop data/static/challenges.yml:1082

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1081|-
1082|  name: 'Steganography'
1083|  category: 'Security through Obscurity'
```

## juice-shop data/static/challenges.yml:1096

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1095|-
1096|  name: 'Successful RCE DoS'
1097|  category: 'Insecure Deserialization'
```

## juice-shop data/static/challenges.yml:1111

- class: `deps`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1110|-
1111|  name: 'Supply Chain Attack'
1112|  category: 'Vulnerable Components'
```

## juice-shop data/static/challenges.yml:1124

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1123|-
1124|  name: 'Two Factor Authentication'
1125|  category: 'Broken Authentication'
```

## juice-shop data/static/challenges.yml:1136

- class: `deps`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1135|-
1136|  name: 'Unsigned JWT'
1137|  category: 'Vulnerable Components'
```

## juice-shop data/static/challenges.yml:1149

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1148|-
1149|  name: 'Upload Size'
1150|  category: 'Improper Input Validation'
```

## juice-shop data/static/challenges.yml:1160

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1159|-
1160|  name: 'Upload Type'
1161|  category: 'Improper Input Validation'
```

## juice-shop data/static/challenges.yml:1183

- class: `xss`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1182|-
1183|  name: 'Video XSS'
1184|  category: 'XSS'
```

## juice-shop data/static/challenges.yml:1200

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1199|-
1200|  name: 'View Basket'
1201|  category: 'Broken Access Control'
```

## juice-shop data/static/challenges.yml:1216

- class: `deps`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1215|-
1216|  name: 'Vulnerable Library'
1217|  category: 'Vulnerable Components'
```

## juice-shop data/static/challenges.yml:1229

- class: `crypto`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1228|-
1229|  name: 'Weird Crypto'
1230|  category: 'Cryptographic Issues'
```

## juice-shop data/static/challenges.yml:1253

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1252|-
1253|  name: 'XXE Data Access'
1254|  category: 'XXE'
```

## juice-shop data/static/challenges.yml:1269

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1268|-
1269|  name: 'XXE DoS'
1270|  category: 'XXE'
```

## juice-shop data/static/challenges.yml:1286

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1285|-
1286|  name: 'Memory Bomb'
1287|  category: 'Insecure Deserialization'
```

## juice-shop data/static/challenges.yml:1302

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1301|-
1302|  name: 'Zero Stars'
1303|  category: 'Improper Input Validation'
```

## juice-shop data/static/challenges.yml:1311

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1310|-
1311|  name: 'Missing Encoding'
1312|  category: 'Improper Input Validation'
```

## juice-shop data/static/challenges.yml:1324

- class: `config`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1323|-
1324|  name: 'Cross-Site Imaging'
1325|  category: 'Security Misconfiguration'
```

## juice-shop data/static/challenges.yml:1339

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1338|-
1339|  name: 'Exposed Metrics'
1340|  category: 'Observability Failures'
```

## juice-shop data/static/challenges.yml:1352

- class: `config`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1351|-
1352|  name: 'Misplaced IaC Files'
1353|  category: 'Security Misconfiguration'
```

## juice-shop data/static/challenges.yml:1365

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1364|-
1365|  name: 'Deluxe Fraud'
1366|  category: 'Improper Input Validation'
```

## juice-shop data/static/challenges.yml:1377

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1376|-
1377|  name: 'CSRF' # FIXME No e2e test automation! No longer works in Chrome >=80 and Firefox >=100 or other latest browsers!
1378|  category: 'Broken Access Control'
```

## juice-shop data/static/challenges.yml:1389

- class: `xss`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1388|-
1389|  name: 'Bonus Payload'
1390|  category: 'XSS'
```

## juice-shop data/static/challenges.yml:1405

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1404|-
1405|  name: 'Reset Uvogin''s Password'
1406|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:1418

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1417|-
1418|  name: 'Meta Geo Stalking'
1419|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:1431

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1430|-
1431|  name: 'Visual Geo Stalking'
1432|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:1442

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1441|-
1442|  name: 'Poison Null Byte'
1443|  category: 'Improper Input Validation'
```

## juice-shop data/static/challenges.yml:1456

- class: `deps`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1455|-
1456|  name: 'Local File Read'
1457|  category: 'Vulnerable Components'
```

## juice-shop data/static/challenges.yml:1474

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1473|-
1474|  name: 'Mass Dispel'
1475|  category: 'Miscellaneous'
```

## juice-shop data/static/challenges.yml:1485

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1484|-
1485|  name: 'Security Advisory'
1486|  category: 'Miscellaneous'
```

## juice-shop data/static/challenges.yml:1494

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1493|-
1494|  name: 'Exposed Credentials'
1495|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:1505

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1504|-
1505|  name: 'Leaked API Key'
1506|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:1517

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1516|-
1517|  name: 'Chatbot Prompt Injection'
1518|  category: 'Injection'
```

## juice-shop data/static/challenges.yml:1531

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1530|-
1531|  name: 'Greedy Chatbot Manipulation'
1532|  category: 'Injection'
```

## juice-shop data/static/challenges.yml:1544

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1543|-
1544|  name: 'AI Debugging'
1545|  category: 'Broken Access Control'
```

## juice-shop data/static/challenges.yml:1558

- class: `other`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1557|-
1558|  name: 'System Prompt Extraction'
1559|  category: 'Injection'
```

## juice-shop data/static/challenges.yml:1571

- class: `secrets`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1570|-
1571|  name: 'Login Cloud Admin'
1572|  category: 'Sensitive Data Exposure'
```

## juice-shop data/static/challenges.yml:1583

- class: `deps`
- source: https://github.com/juice-shop/juice-shop/blob/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4/data/static/challenges.yml
- opinion: **NO**. This line is a challenge title in the catalog, not the vulnerable statement.

```
1582|-
1583|  name: 'Vulnerable Infrastructure'
1584|  category: 'Vulnerable Components'
```

## dvna core/appHandler.js:10

- class: `sqli`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a1-injection.md
- opinion: **YES**. The code on this line matches the class and the description.

```
9|module.exports.userSearch = function (req, res) {
10|	var query = "SELECT name,id FROM Users WHERE login='" + req.body.login + "'";
11|	db.sequelize.query(query, {
```

## dvna core/appHandler.js:39

- class: `cmdi`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a1-injection.md
- opinion: **YES**. The code on this line matches the class and the description.

```
38|module.exports.ping = function (req, res) {
39|	exec('ping -c 2 ' + req.body.address, function (err, stdout, stderr) {
40|		output = stdout + stderr
```

## dvna core/authHandler.js:49

- class: `crypto`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a2-broken-auth.md
- opinion: **YES**. The code on this line matches the class and the description.

```
48|			if (user) {
49|				if (req.query.token == md5(req.query.login)) {
50|					res.render('resetpw', {
```

## dvna server.js:24

- class: `secrets`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a2-broken-auth.md
- opinion: **YES**. The code on this line matches the class and the description.

```
23|app.use(session({
24|  secret: 'keyboard cat',
25|  resave: true,
```

## dvna core/appHandler.js:206

- class: `other`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a3-sensitive-data-exposure.md
- opinion: **unsure**. The line only starts listUsersAPI. The password-hash response is not on this line.

```
205|
206|module.exports.listUsersAPI = function (req, res) {
207|	db.User.findAll({}).then(users => {
```

## dvna core/appHandler.js:235

- class: `other`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a4-xxe.md
- opinion: **YES**. The code on this line matches the class and the description.

```
234|	if (req.files.products && req.files.products.mimetype=='text/xml'){
235|		var products = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), {noent:true,noblanks:true})
236|		products.root().childNodes().forEach( product => {
```

## dvna routes/app.js:1

- class: `other`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a5-broken-access-control.md
- opinion: **NO**. The line only imports the router. It does not show the missing admin check or a CSRF token.

```
1|var router = require('express').Router()
2|var appHandler = require('../core/appHandler')
```

## dvna core/appHandler.js:197

- class: `config`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a6-securty-misconfig.md
- opinion: **NO**. The line is mathjs.eval of req.body.eqn, which is code injection, not a stack leak.

```
196|		res.render('app/calc', {
197|			output: mathjs.eval(req.body.eqn)
198|		})
```

## dvna core/appHandler.js:197

- class: `eval`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a1-injection.md
- opinion: **YES**. The code on this line matches the class and the description.

```
196|		res.render('app/calc', {
197|			output: mathjs.eval(req.body.eqn)
198|		})
```

## dvna views/app/products.ejs:20

- class: `xss`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a7-xss.md
- opinion: **YES**. The code on this line matches the class and the description.

```
19|            <p class="bg-success">
20|                Listing products with <strong>search query: </strong> <%- output.searchTerm %>
21|                &nbsp; &nbsp;
```

## dvna views/app/products.ejs:50

- class: `xss`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a7-xss.md
- opinion: **YES**. The code on this line matches the class and the description.

```
49|                <td><%- output.products[i].id %></td>
50|                <td><%- output.products[i].name %></td>
51|                <td><%- output.products[i].code %></td>
```

## dvna views/app/adminusers.ejs:40

- class: `xss`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a7-xss.md
- opinion: **YES**. The code on this line matches the class and the description.

```
39|                var c_email = row.insertCell(2);
40|                c_id.innerHTML = users[i].id;
41|                c_name.innerHTML = users[i].name;
```

## dvna core/appHandler.js:218

- class: `other`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a8-insecure-deserialization.md
- opinion: **YES**. The code on this line matches the class and the description.

```
217|	if(req.files.products){
218|		var products = serialize.unserialize(req.files.products.data.toString('utf8'))
219|		products.forEach( function (product) {
```

## dvna package.json:25

- class: `deps`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a9-using-components-with-known-vulnerability.md
- opinion: **YES**. The code on this line matches the class and the description.

```
24|    "libxmljs": "^0.19.1",
25|    "mathjs": "3.10.1",
26|    "md5": "^2.2.1",
```

## dvna server.js:15

- class: `other`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/a10-insufficient-logging.md
- opinion: **unsure**. morgan tiny is on this line, but the claimed bug is the absence of audit logs.

```
14|app.set('view engine','ejs')
15|app.use(morgan('tiny'))
16|app.use(bodyParser.urlencoded({ extended: false }))
```

## dvna routes/app.js:1

- class: `other`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/ax-csrf.md
- opinion: **NO**. The line only imports the router. It does not show the missing admin check or a CSRF token.

```
1|var router = require('express').Router()
2|var appHandler = require('../core/appHandler')
```

## dvna core/appHandler.js:188

- class: `redirect`
- source: https://github.com/appsecco/dvna/blob/9ba473add536f66ac9007966acb2a775dd31277a/docs/solution/ax-unvalidated-redirects-and-forwards.md
- opinion: **YES**. The code on this line matches the class and the description.

```
187|	if (req.query.url) {
188|		res.redirect(req.query.url)
189|	} else {
```

## goof routes/index.js:52

- class: `nosqli`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/README.md
- opinion: **YES**. The code on this line matches the class and the description.

```
51|  if (validator.isEmail(req.body.username)) {
52|    User.find({ username: req.body.username, password: req.body.password }, function (err, users) {
53|      if (users.length > 0) {
```

## goof routes/index.js:74

- class: `redirect`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/README.md
- opinion: **YES**. The code on this line matches the class and the description.

```
73|  if (redirectPage) {
74|      return res.redirect(redirectPage)
75|  } else {
```

## goof views/admin.ejs:17

- class: `xss`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/README.md
- opinion: **YES**. The code on this line matches the class and the description.

```
16|      <center>
17|      <input type="hidden" name="redirectPage" value="<%- redirectPage %>" />
18|      <input type="submit">
```

## goof views/index.ejs:20

- class: `xss`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/exploits/marked-exploit.sh
- opinion: **YES**. The code on this line matches the class and the description.

```
19|  <div class="item">
20|    <a class="update-link" href="/edit/<%= todo._id %>" title="Update this todo item"><%- marked(new String(todo.content)) %></a>
21|    <a class="del-btn" href="/destroy/<%= todo._id %>" title="Delete this todo item">Delete</a>
```

## goof routes/index.js:174

- class: `cmdi`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/exploits/shell-injection.md
- opinion: **YES**. The code on this line matches the class and the description.

```
173|
174|    exec('identify ' + url, function (err, stdout, stderr) {
175|      console.log(err);
```

## goof app.js:43

- class: `secrets`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/README.md
- opinion: **YES**. The code on this line matches the class and the description.

```
42|app.use(session({
43|  secret: 'keyboard cat',
44|  name: 'connect.sid',
```

## goof routes/index.js:360

- class: `proto`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/exploits/prototype-pollution.sh
- opinion: **YES**. The code on this line matches the class and the description.

```
359|
360|    _.merge(message, req.body.message, {
361|      id: lastId++,
```

## goof package.json:35

- class: `deps`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/README.md
- opinion: **YES**. The code on this line matches the class and the description.

```
34|    "lodash": "4.17.4",
35|    "marked": "0.3.5",
36|    "method-override": "latest",
```

## goof package.json:46

- class: `deps`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/README.md
- opinion: **NO**. Line 46 is stream-buffers. st@0.2.4 is the previous line.

```
45|    "st": "0.2.4",
46|    "stream-buffers": "^3.0.1",
47|    "tap": "^11.1.3",
```

## goof app.js:28

- class: `config`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/README.md
- opinion: **unsure**. The line only creates the Express app. Missing headers are not shown here.

```
27|
28|var app = express();
29|var routes = require('./routes');
```

## goof routes/index.js:270

- class: `path`
- source: https://github.com/snyk-labs/nodejs-goof/tree/add14ba59e98240d9e00a235dd7d42cd61ae9912/exploits/zip-slip
- opinion: **YES**. The code on this line matches the class and the description.

```
269|    var extracted_path = "/tmp/extracted_files";
270|    zip.extractAllTo(extracted_path, true);
271|    data = "No backup.txt file found";
```

## goof routes/index.js:313

- class: `eval`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/exploits/dustjs-exploits.sh
- opinion: **unsure**. The line renders a Dust template. The query value named in the description is not on this line.

```
312|  console.log(JSON.stringify(req.query));
313|  return res.render("about_new.dust",
314|    {
```

## goof routes/index.js:120

- class: `path`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/README.md
- opinion: **unsure**. The line renders account.hbs with a profile object. A layout override is not visible on this line.

```
119|    // render the view
120|    return res.render('account.hbs', profile)
121|  } else {
```

## goof routes/index.js:106

- class: `other`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/README.md
- opinion: **YES**. The code on this line matches the class and the description.

```
105|  // validate the input
106|  if (validator.isEmail(profile.email, { allow_display_name: true })
107|    // allow_display_name allows us to receive input as:
```

## goof app.js:45

- class: `config`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/README.md
- opinion: **YES**. The code on this line matches the class and the description.

```
44|  name: 'connect.sid',
45|  cookie: { path: '/' }
46|}))
```

## goof app.js:12

- class: `other`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/README.md
- opinion: **NO**. Requiring the http module is not by itself an insecure-protocol bug.

```
11|var express = require('express');
12|var http = require('http');
13|var path = require('path');
```

## goof routes/index.js:330

- class: `crypto`
- source: https://github.com/snyk-labs/nodejs-goof/blob/add14ba59e98240d9e00a235dd7d42cd61ae9912/exploits/prototype-pollution.sh
- opinion: **YES**. The code on this line matches the class and the description.

```
329|  // You don't know password for the admin.
330|  { name: 'admin', password: Math.random().toString(32), canDelete: true },
331|];
```

## vulnerable-node routes/tools.js:21

- class: `ssrf`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/02-ssrf-imds.md
- opinion: **YES**. The code on this line matches the class and the description.

```
20|  try {
21|    const response = await fetch(req.body.url, {
22|      headers: req.body.token ? { Authorization: "Bearer " + req.body.token } : {},
```

## vulnerable-node model/db.js:14

- class: `sqli`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/03-sqli.md
- opinion: **YES**. The code on this line matches the class and the description.

```
13|  const q = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
14|  return pool.query(q);
15|}
```

## vulnerable-node model/db.js:26

- class: `sqli`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/03-sqli.md
- opinion: **YES**. The code on this line matches the class and the description.

```
25|    "SELECT * FROM products WHERE name ILIKE '%" + q + "%' OR description ILIKE '%" + q + "%'";
26|  return pool.query(sql);
27|}
```

## vulnerable-node model/db.js:101

- class: `sqli`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/03-sqli.md
- opinion: **YES**. The code on this line matches the class and the description.

```
100|function ordersForUserSorted(userId, sort) {
101|  return pool.query(`SELECT * FROM orders WHERE user_id = $1 ORDER BY ${sort} DESC`, [userId]);
102|}
```

## vulnerable-node routes/shop.js:41

- class: `nosqli`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/03b-nosql.md
- opinion: **YES**. The code on this line matches the class and the description.

```
40|    const filter = { origin: req.body.tags }; // raw user JSON into Mongo query
41|    const docs = await col.find(filter).toArray();
42|    res.json({ count: docs.length, docs });
```

## vulnerable-node routes/shop.js:58

- class: `nosqli`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/03b-nosql.md
- opinion: **YES**. The code on this line matches the class and the description.

```
57|    if (req.query.origin) query.origin = req.query.origin; // GET-based NoSQL too
58|    const docs = await col.find(query).limit(50).toArray();
59|    res.json({ docs });
```

## vulnerable-node views/product_detail.ejs:71

- class: `xss`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/05-xss-token-theft.md
- opinion: **YES**. The code on this line matches the class and the description.

```
70|        <!-- VULN (A05, stored XSS): body renders unescaped -->
71|        <p><%- r.body %></p>
72|      </div>
```

## vulnerable-node middleware/auth.js:30

- class: `jwt`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/07-jwt-weak-secret.md
- opinion: **unsure**. The line verifies a JWT with config.jwtSecret. The weak secret value is not on this line.

```
29|  try {
30|    req.apiUser = jwt.verify(token, config.jwtSecret);
31|    next();
```

## vulnerable-node views/error.ejs:4

- class: `config`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/09-misconfig-debug.md
- opinion: **YES**. The code on this line matches the class and the description.

```
3|  <!-- VULN (A02/A10): stack trace rendered to the user when DEBUG_ERRORS=1. -->
4|  <pre class="error-box"><%= error.stack %></pre>
5|<% } %>
```

## vulnerable-node routes/account.js:45

- class: `proto`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/13-prototype-pollution.md
- opinion: **YES**. The code on this line matches the class and the description.

```
44|  const prefs = global.userPrefs[req.session.username] || {};
45|  merge(prefs, req.body || {});
46|  global.userPrefs[req.session.username] = prefs;
```

## vulnerable-node routes/extras.js:17

- class: `path`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/15-path-traversal.md
- opinion: **YES**. The code on this line matches the class and the description.

```
16|  const full = path.join(IMG_DIR, name);
17|  fs.readFile(full, (err, data) => {
18|    if (err) return res.status(404).render("error", { message: "File not found", error: {} });
```

## vulnerable-node routes/extras.js:33

- class: `cmdi`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/16-command-injection.md
- opinion: **YES**. The code on this line matches the class and the description.

```
32|  const host = req.body.host || "127.0.0.1";
33|  exec(`ping -c 2 "${host}"`, { timeout: 6000 }, (err, stdout) => {
34|    res.render("ping", { output: (stdout || String(err)).slice(0, 4000), host });
```

## vulnerable-node routes/orders.js:66

- class: `other`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/01-bola-idor.md
- opinion: **unsure**. The line declares the order route. The missing owner check is not on this line.

```
65|// SAFE: add "AND user_id = $2" with the session user id.
66|router.get("/orders/:id", requireLogin, async (req, res, next) => {
67|  try {
```

## vulnerable-node routes/account.js:30

- class: `other`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/04-mass-assignment.md
- opinion: **YES**. The code on this line matches the class and the description.

```
29|  try {
30|    await db.updateProfile(req.session.userId, req.body);
31|    if (req.body.role) req.session.role = req.body.role;
```

## vulnerable-node routes/orders.js:28

- class: `other`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/06-price-tamper-checkout.md
- opinion: **YES**. The code on this line matches the class and the description.

```
27|    }
28|    const amount = parseInt(b.amount_cents, 10);
29|    const item = {
```

## vulnerable-node routes/orders.js:22

- class: `other`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/06b-csrf.md
- opinion: **unsure**. The line declares checkout. The missing CSRF token is not on this line.

```
21|// tokenize the card via the payment provider.
22|router.post("/checkout", async (req, res, next) => {
23|  try {
```

## vulnerable-node routes/auth.js:23

- class: `other`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/10-logging-failures.md
- opinion: **YES**. The code on this line matches the class and the description.

```
22|  const password = req.body.password;
23|  console.log(`[auth] login attempt user=${user} password=${password}`); // VULN (A09): password in logs
24|  try {
```

## vulnerable-node .github/workflows/ci.yml:7

- class: `other`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/11-poisoned-pipelines.md
- opinion: **unsure**. The line is a comment describing pull_request_target. It is not the workflow trigger.

```
6|# Bugs baked in:
7|#   1. pull_request_target checks out the PR head and runs it with secrets
8|#   2. untrusted PR title interpolated into a run: shell command
```

## vulnerable-node README.md:133

- class: `secrets`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/12-secrets-in-git.md
- opinion: **NO**. The line is prose about a token that used to be in git history. The token value is not here.

```
132|
133|An early commit added a fake `.env` with `PIPELINE_TOKEN`. A later commit removed it from `HEAD`. The value remains in history:
134|
```

## vulnerable-node routes/tools.js:44

- class: `other`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/14-redos.md
- opinion: **YES**. The code on this line matches the class and the description.

```
43|  try {
44|    const re = new RegExp(pattern);
45|    const match = re.test(input);
```

## vulnerable-node Dockerfile:21

- class: `config`
- source: https://github.com/cr0hn/vulnerable-node/blob/d68f2a3c9277ece2c2feb9976052033bdecd7fbe/docs/labs/17-docker-hardening.md
- opinion: **NO**. The line is USER node. This checkout does not run the image as root.

```
20|RUN chown -R node:node /app
21|USER node
22|
```
