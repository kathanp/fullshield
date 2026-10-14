'use strict';
const { exec } = require('child_process');
module.exports = function runLlm(completion) {
  exec(completion.choices[0].message.content);
};
