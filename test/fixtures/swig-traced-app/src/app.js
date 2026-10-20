'use strict';
app.set('view engine', 'swig');

app.get('/search', (req, res) => {
  res.render('item', { name: req.query.name, title: 'static' });
});

db.collection('users').findOne(req.params.id, (err, doc) => {
  res.render('profile', { ...doc, footer: 'static' });
});

app.get('/save', (req, res) => {
  res.locals.csrftoken = req.csrfToken();
  res.render('token', { token: req.csrfToken(), extra: res.locals.csrfToken, hidden: res.locals._csrf });
});
