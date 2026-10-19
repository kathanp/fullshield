const { MongoClient } = require('mongodb');
const schema = Joi.object({ name: Joi.string().required() });

app.post('/joi', validate(schema), (req, res) => {
  collection.findOne({ name: req.body.name });
});
