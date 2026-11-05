const fastify = require('fastify')();

fastify.post('/in', (request) => {
  db.query(request.body.name);
});
