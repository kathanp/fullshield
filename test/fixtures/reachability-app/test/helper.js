'use strict';
// Test-only import must not make unused production lodash "reachable".
const lodash = require('lodash');
lodash.get({}, 'x');
