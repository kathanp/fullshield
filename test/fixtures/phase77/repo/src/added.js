// Positive Phase 77 fixture: a non-literal eval argument is SAST-EVAL-001.
function run(code) {
  return eval(code);
}

module.exports = { run };
