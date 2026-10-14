'use strict';
const openai = require('openai');
module.exports = async function chat(req) {
  return openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'system', content: 'You are a helper. User said: ' + req.body.q }],
  });
};
