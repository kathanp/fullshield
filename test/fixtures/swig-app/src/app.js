'use strict';
app.set('view engine', 'swig');
res.render('item', { name: req.query.name });
