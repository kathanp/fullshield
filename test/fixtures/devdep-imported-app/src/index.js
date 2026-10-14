'use strict';
const express = require('express');
const lodash = require('lodash');
const app = express();
app.get('/', (_req, res) => res.json(lodash.get({}, 'x')));
app.listen(3000);
