'use strict';
app.set('view engine', 'swig');

app.get('/search', (req, res) => {
  res.render('item', { name: req.query.name, title: 'static' });
});

db.collection('users').findOne(req.params.id, (err, doc) => {
  res.render('profile', { ...doc, footer: 'static' });
});
