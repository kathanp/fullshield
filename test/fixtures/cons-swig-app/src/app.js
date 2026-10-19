'use strict';
const consolidate = require('consolidate');
app.engine('.html', consolidate.swig);
app.set('view engine', 'html');
