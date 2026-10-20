'use strict';
const consolidate = require('consolidate');
app.engine('.html', consolidate.handlebars);
app.set('view engine', 'html');
