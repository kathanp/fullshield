'use strict';
const jwt = require('jsonwebtoken');
const app = {};

const JWT_SECRET = 'super-secret-jwt-signing-key-fixture';
const UNUSED_TOKEN = 'sk_test_' + 'FAKEfakeFAKEfakeFAKE1234';

app.get('/token', (req, res) => {
  res.json(jwt.sign({ sub: 'a' }, JWT_SECRET));
});
