const fs = require('fs');
const token = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
console.log('npmrc bytes', token.length);
