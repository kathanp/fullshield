'use strict';
module.exports = (openai, messages) =>
  openai.chat.completions.create({ model: 'gpt-4o-mini', messages });
