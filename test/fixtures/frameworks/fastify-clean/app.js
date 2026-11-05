const fastify = require('fastify')();

fastify.post('/in', { schema }, (request) => {
  db.query(request.body.name);
});
