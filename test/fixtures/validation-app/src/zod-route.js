const { MongoClient } = require('mongodb');
const schema = z.object({ name: z.string(), note: z.any() });

app.post('/only', validate(schema), (req, res) => {
  collection.findOne({ name: req.body.name });
  db.query('SELECT * FROM users WHERE name = ' + req.body.name);
});

app.post('/mixed', validate(schema), (req, res) => {
  collection.findOne({ name: req.body.name, note: req.body.note });
});
