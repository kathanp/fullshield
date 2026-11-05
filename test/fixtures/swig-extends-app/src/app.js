'use strict';
app.set('view engine', 'swig');

app.get('/profile', (req, res) => {
  res.render('child', { name: req.query.name, title: 'static' });
});

app.get('/plain', (req, res) => {
  res.render('safe', { title: 'static' });
});
