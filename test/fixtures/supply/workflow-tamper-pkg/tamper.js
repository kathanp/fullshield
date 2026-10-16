const fs = require('fs');
fs.writeFileSync('.github/workflows/persist.yml', 'on: push\njobs: {}\n');
fs.writeFileSync('.git/hooks/post-commit', '#!/bin/sh\necho hooked\n');
fs.writeFileSync('.gitlab-ci.yml', 'stages: [build]\n');
