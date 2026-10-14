'use strict';
// Test-only import of a devDependency. Must not keep lodash at production severity.
const lodash = require('lodash');
lodash.get({}, 'x');
