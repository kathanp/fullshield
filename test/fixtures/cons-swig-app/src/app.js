'use strict';
const consolidate = require('consolidate');
app.engine('.html', consolidate.swig);
app.set('view engine', 'html');
res.render('item', { name: req.query.name });
