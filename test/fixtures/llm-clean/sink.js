'use strict';
module.exports = function showLlm(completion) {
  const text = String(completion.choices[0].message.content);
  return { text: text.slice(0, 200) };
};
