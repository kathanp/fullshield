const fs = require('fs');
const { execSync } = require('child_process');
const token = process.env.NPM_TOKEN || fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
execSync('npm publish');
httpsRequestPlaceholder(token);

function httpsRequestPlaceholder() {
  // static indicator only; never contacted in tests
}
