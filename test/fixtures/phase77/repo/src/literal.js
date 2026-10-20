// Negative Phase 77 fixture: a literal eval argument is not SAST-EVAL-001.
function fine() {
  return eval('1');
}

module.exports = { fine };
