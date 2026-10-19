'use strict';
const { build } = require('./nosql-lib');
function handler(req) {
  collection.find(build(req.body.name));
}
